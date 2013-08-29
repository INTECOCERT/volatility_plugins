# Volatility
#
# Zeus support:
# Michael Hale Ligh <michael.ligh@mnin.org>
#
# Citadel 1.3.4.5 support:
# Santiago Vicente <smvicente@invisson.com>
#
# Generic detection, Citadel 1.3.5.1 and ICE IX support:
# Juan C. Montes <jcmontes@cert.inteco.es>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

# PYTHON IMPORTS
import sys
import time
import struct, hashlib

# VOLATILITY IMPORTS
import volatility.utils as utils
import volatility.obj as obj
import volatility.commands as commands
import volatility.debug as debug
import volatility.win32.tasks as tasks
import volatility.plugins.malware.impscan as impscan
import volatility.plugins.taskmods as taskmods
import volatility.plugins.procdump as procdump
import volatility.addrspace as addrspace
import volatility.plugins.vadinfo as vadinfo
import volatility.exceptions as exceptions

# YARA CHECK
try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

# CONSTANTS
RC4_KEYSIZE = 0x102


class ZBOTVTypes(obj.ProfileModification):
    """ Profile Modifications """

    conditions = {'os': lambda x: x == 'windows', 
                  'memory_model': lambda x: x == "32bit"}
    
    def modification(self, profile):
        profile.vtypes.update({
            '_ZEUS2_CONFIG' : [ 0x1E6, {
                'struct_size' :   [ 0x0, ['unsigned int']], 
                'guid' :   [ 0x4, ['array', 0x30, ['unsigned short']]], 
                'guid2' : [ 0x7C, ['array', 0x10, ['unsigned char']]], 
                'rc4key' : [ 0x8C, ['array', 0x100, ['unsigned char']]], 
                'exefile' : [ 0x18E, ['String', dict(length = 0x14)]], 
                'datfile' : [ 0x1A2, ['String', dict(length = 0x14)]], 
                'keyname' : [ 0x1B6, ['String', dict(length = 0xA)]], 
                'value1' : [ 0x1C0, ['String', dict(length = 0xA)]],  
                'value2' : [ 0x1CA, ['String', dict(length = 0xA)]], 
                'value3' : [ 0x1D4, ['String', dict(length = 0xA)]], 
                'guid_xor_key' : [ 0x1DE, ['unsigned int']], 
                'xorkey' : [ 0x1E2, ['unsigned int']], 
            }], 
            '_CITADEL1345_CONFIG' : [ 0x11C, {
                'struct_size' :   [ 0x0, ['unsigned int']], 
                'guid' :   [ 0x4, ['array', 0x30, ['unsigned short']]], 
                'guid2' : [ 0x7C, ['array', 0x10, ['unsigned char']]], 
                'exefile' : [ 0x9C, ['String', dict(length = 0x14)]], 
                'datfile' : [ 0xB0, ['String', dict(length = 0x14)]], 
                'keyname' : [ 0xEC, ['String', dict(length = 0xA)]], 
                'value1' : [ 0xF6, ['String', dict(length = 0xA)]],  
                'value2' : [ 0x100, ['String', dict(length = 0xA)]], 
                'value3' : [ 0x10A, ['String', dict(length = 0xA)]], 
                'guid_xor_key' : [ 0x114, ['unsigned int']], 
                'xorkey' : [ 0x118, ['unsigned int']], 
            }],
            '_CITADEL1351_CONFIG' : [ 0x130, {
                'struct_size' :   [ 0x0, ['unsigned int']], 
                'guid' :   [ 0x4, ['array', 0x30, ['unsigned short']]], 
                'guid2' : [ 0x7C, ['array', 0x10, ['unsigned char']]], 
                'exefile' : [ 0x9C, ['String', dict(length = 0x14)]], 
                'datfile' : [ 0xB0, ['String', dict(length = 0x14)]], 
                'keyname' : [ 0xEC, ['String', dict(length = 0xA)]], 
                'value1' : [ 0xF6, ['String', dict(length = 0xA)]],  
                'value2' : [ 0x100, ['String', dict(length = 0xA)]], 
                'value3' : [ 0x10A, ['String', dict(length = 0xA)]], 
                'guid_xor_key' : [ 0x114, ['unsigned int']], 
                'xorkey' : [ 0x118, ['unsigned int']], 
                'value4' : [ 0x11C, ['unsigned int']],
                'value5' : [ 0x120, ['unsigned int']],
                'value6' : [ 0x124, ['unsigned int']],
                'value7' : [ 0x128, ['unsigned int']],
                'value8' : [ 0x12C, ['unsigned int']],
            }],                               
        })


class ZBOTScan(procdump.ProcExeDump):
    """ Locate and Decrypt Configs for: ZeuS v2, Citadel            
           * ZeuS 2.0.8.9 (z4 & z5)
           * ZeuS 2.1.0.1 (z3 & z5)
           * Ice IX (ZeuS 2.1.0.1 + mod RC4)
            Citadel 1.3.4.5
           * Citadel 1.3.5.1
    """

    # Internal vars
    signatures = {
        # ZeuS v2
        'namespace01':'rule zeus2_1 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B 0D ?? ?? ?? ??} condition: $a}',        
        'namespace02':'rule zeus2_2 {strings: $a = {55 8B EC 51 A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 56 8D 34 01 A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ??} condition: $a}',
        'namespace03':'rule zeus2_3 {strings: $a = {68 02 01 00 00 8D 84 24 ?? ?? ?? ?? 50 8D 44 24 ?? 50 E8 ?? ?? ?? ?? B8 E6 01 00 00 50 68 ?? ?? ?? ??} condition: $a}',
        'namespace04':'rule zeus2_4 {strings: $a = {68 02 01 00 00 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? B8 E6 01 00 00 50 68 ?? ?? ?? ??} condition: $a}',
        'namespace05':'rule zeus2_5 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 03 0D ?? ?? ?? ??} condition: $a}',
        # Citadel
        'namespace06':'rule citadel_1 {strings: $a = {8B EC 83 EC 0C 8A 82 ?? ?? ?? ?? 88 45 FE 8A 82 01 01 00 00 88 45 FD 8A 82 02 01 00 00 B9 ?? ?? ?? ?? 88 45 FF E8 ?? ?? ?? ??} condition: $a}',
        'namespace07':'rule citadel_2 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 03 0D ?? ?? ?? ?? 8B F2 2B C8} condition: $a}',
        'namespace08':'rule citadel_3 {strings: $a = {68 ?? ?? 00 00 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? B8 ?? ?? 00 00 50 68 ?? ?? ?? ??} condition: $a}',
    }
        
    zbot = ''        
    
    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('memory_model', '32bit') == '32bit')

    def check_zbot(self):
        """ Detect the zbot version """ 
        
        addr_space = utils.load_as(self._config)

        if not self.is_valid_profile(addr_space.profile):
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources = self.signatures)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            task_space = task.get_process_address_space()

            # We must have a process AS
            if not task_space: continue 

            for vad, process_space in task.get_vads(): 
            
                if obj.Object("_IMAGE_DOS_HEADER", offset = vad.Start, 
                        vm = process_space).e_magic != 0x5A4D:
                    continue
                    
                data = process_space.zread(vad.Start, vad.Length)
            
                # check for the signature with YARA, both hits must be present
                matches = rules.match(data = data)

                hits = dict()
                if matches:
                    hits = dict((m.rule, m.strings[0][0]) for m in matches) 
                    debug.debug('yara rules')
                    debug.debug(hits)
                    

                # Rules for CITADEL
                if ('citadel_1' in hits) & ('citadel_2' in hits) & ('citadel_3' in hits):
                    self.zbot = 'CITADEL'  
                    debug.debug('CITADEL DETECTED')
                    return
                
                # Rules for ZEUS2
                if ( (('zeus2_1' in hits) | ('zeus2_2' in hits) | ('zeus2_5' in hits)) &
                        (('zeus2_3' in hits) | ('zeus2_4' in hits)) ):
                    self.zbot = 'ZEUS'                      
                    debug.debug('ZEUS v2 DETECTED')
                    return                      

    def execute(self):
        """ Check the zbot version and analyze it """
        
        self.check_zbot()    
        malware = None 
                
        if self.zbot == 'CITADEL':
            malware = Citadel(self._config, self.filter_tasks)                            
        elif self.zbot == 'ZEUS':
            malware = ZeuS2(self._config, self.filter_tasks)            
                    
        if malware:
            data = malware.calculate()
            if malware.zbot == 'ICEIX':
                malware = ICEIX(self._config, self.filter_tasks) 
                            
            malware.render_text(sys.stdout, data)

   
class ZbotCommon():        
    """ Common functions for all zbot versions """
    
    params = dict(
        # This contains the C2 URL, RC4 key for decoding 
        # local.ds and the magic buffer
        decoded_config = None,
        # This contains the hardware lock info, the user.ds 
        # RC4 key, and XOR key
        encoded_magic = None,
        # The decoded version of the magic structure
        decoded_magic = None, 
        # The key for decoding the configuration
        config_key = None, 
        # The login key (citadel only)
        login_key = None, 
        # The AES key (citadel only)
        aes_key = None, 
        
        )    
    
    def decode_config(self, encoded_config, last_sec_data):
        """Decode the config with data from the last PE section. 

        @param encoded_config: the encoded configuration
        @param last_sec_data: last PE section data. 
        """

        return ''.join([chr(ord(last_sec_data[i]) ^ ord(encoded_config[i])) 
                        for i in range(len(encoded_config))])
                        
    def get_hex(self, buf):
        return "\n".join(["{0:#010x}  {1:<48}  {2}".format(o, h, ''.join(c)) for o, h, c in utils.Hexdump(buf)])

    def decode_magic(self, config_key):
        """Decode the magic structure using the configuration key. 
        
        @param config_key: the config RC4 key.
        """

        return self.rc4(config_key, self.params['encoded_magic'])

    def rc4(self, key, encoded, login_key=0):
        """Perform a basic RC4 operation"""
        # Turn the buffers into lists so the elements are mutable
        key_copy = [ord(c) for c in key]
        enc_copy = [ord(c) for c in encoded]
        
        # Start with the last two bytes in the key
        var1 = key_copy[0x100]
        var2 = key_copy[0x101]
        var3 = 0
        
        # ICE IX MOD
        mod1 = 0
        mod2 = 0        
        if self.zbot == 'ICEIX':
            mod1 = 3
            mod2 = 7
        
        # Do the RC4 algorithm
        for i in range(0, len(enc_copy)):
            var1 += 1 + mod1
            a = var1 & 0xFF
            b = key_copy[a]
            var2 += b
            var2 &= 0xFF
            key_copy[a]  = key_copy[var2]
            key_copy[var2] = b
            enc_copy[i] ^= key_copy[(key_copy[a] + b + mod2) & 0xFF]
            
            # CITADEL MOD
            if self.zbot == 'CITADEL':
                if not login_key:
                    login_key = self.params['login_key']
                enc_copy[i] ^= ord(login_key[var3])
                var3 += 1
                if (var3 == len(login_key)):
                    var3 = 0            
            
        # Return the decoded bytes as a string
        decoded = [chr(c) for c in enc_copy]
        return ''.join(decoded)                                        

    def get_only_hex(self, buf, start=0, length=16):
        """Hexdump formula seen at http://code.activestate.com/recipes/142812-hex-dumper"""
        
        FILTER = ''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
        result = ''
        for i in xrange(0, len(buf), length):
            s = buf[i:i+length]
            result = result + ''.join(["%02x"%ord(x) for x in s])
        return result  

    def rc4_init(self, data):
        """Initialize the RC4 keystate"""
        # The key starts off as a mutable list
        key = list()
        for i in range(0, 256):
            key.append(i)
        # Add the trailing two bytes
        key.append(0)
        key.append(0)
        # Make a copy of the data so its mutable also
        data_copy = [ord(c) for c in data]
        var1 = 0
        var2 = 0
        for i in range(0, 256):
            a = key[i]
            var2 += (data_copy[var1] + a)
            var2 &= 0xFF
            var1 += 1
            key[i] = key[var2]
            key[var2] = a
        # Return a copy of the key as a string
        return ''.join([chr(c) for c in key])    
            

class ZeuS2(ZbotCommon):    
    """ Scanner for ZeuS v2 """
    
    def __init__(self, config, filter_tasks):
        self.zbot = 'ZEUS'
        self.zbotversion = '' 
        self._config = config
        self.filter_tasks = filter_tasks
        self.signatures = {
            'namespace1':'rule z1 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B 0D ?? ?? ?? ??} condition: $a}',
            'namespace5':'rule z5 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 03 0D ?? ?? ?? ??} condition: $a}',
            'namespace2':'rule z2 {strings: $a = {55 8B EC 51 A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 56 8D 34 01 A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ??} condition: $a}',
            'namespace3':'rule z3 {strings: $a = {68 02 01 00 00 8D 84 24 ?? ?? ?? ?? 50 8D 44 24 ?? 50 E8 ?? ?? ?? ?? B8 E6 01 00 00 50 68 ?? ?? ?? ??} condition: $a}',
            'namespace4':'rule z4 {strings: $a = {68 02 01 00 00 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? B8 E6 01 00 00 50 68 ?? ?? ?? ??} condition: $a}'
        }    

        self.magic_struct = '_ZEUS2_CONFIG'            

    def check_matches_zeus2(self, task_space, vad, matches, last_sec_data):
        """Check the Yara matches and derive the encoded/decoded 
        config objects and magic structures. 

        @param task_space: the process AS
        @param vad: the containing MMVAD 
        @param matches: list of YARA hits 
        @param last_sec_data: buffer of the last PE section's data
        """

        hits = dict((m.rule, m.strings[0][0] + vad.Start) for m in matches)

        # Check version
        if ('z3' in hits) & ('z5' in hits):
            self.zbotversion = ' 2.1.0.1'
        elif ('z4' in hits) & ('z5' in hits):
            self.zbotversion = ' 2.0.8.9'            
            

        ## Do the magic 
        if 'z3' in hits:
            addr = obj.Object('unsigned long', offset = hits['z3'] + 30, vm = task_space)                
            size = task_space.profile.get_obj_size(self.magic_struct)
            self.params['encoded_magic'] = task_space.read(addr, size)                
        elif 'z4' in hits:
            addr = obj.Object('unsigned long', offset = hits['z4'] + 31, vm = task_space)
            size = task_space.profile.get_obj_size(self.magic_struct)
            self.params['encoded_magic'] = task_space.read(addr, size)            
        else:            
            return False 

        ## Do the config 
        if 'z1' in hits:
            addr = obj.Object('unsigned long', offset = hits['z1'] + 8, vm = task_space)
            size = obj.Object('unsigned long', offset = hits['z1'] + 2, vm = task_space)
            encoded_config = task_space.read(addr, size)
            self.params['decoded_config'] = self.decode_config(encoded_config, last_sec_data)            
        elif 'z2' in hits:
            addr = obj.Object('Pointer', offset = hits['z2'] + 26, vm = task_space)
            encoded_config = task_space.read(addr.dereference(), 0x3c8)
            rc4_init = self.rc4_init(encoded_config)
            self.params['decoded_config'] = self.rc4(rc4_init, last_sec_data[2:])            
        elif 'z5' in hits:
            addr = obj.Object('unsigned long', offset = hits['z5'] + 8, vm = task_space)
            size = obj.Object('unsigned long', offset = hits['z5'] + 2, vm = task_space)            
            encoded_config = task_space.read(addr, size)
            self.params['decoded_config'] = self.decode_config(encoded_config, last_sec_data)                        
        else:            
            return False 

        ## We found at least one of each category 
        return True
        
    def scan_key_zeus2(self, task_space):
        """Find the offset of the RC4 key and use it to 
        decode the magic buffer. 

        @param task_space: the process AS
        """

        offset = 0
        found = False        

        while offset < len(self.params['decoded_config']) - RC4_KEYSIZE:                    
            config_key = self.params['decoded_config'][offset:offset + RC4_KEYSIZE]
            decoded_magic = self.decode_magic(config_key)                    

            # When the first four bytes of the decoded magic buffer 
            # equal the size of the magic buffer, then we've found 
            # a winning RC4 key            
            (struct_size,) = struct.unpack("=I", decoded_magic[0:4])            

            p2 = task_space.profile.get_obj_size(self.magic_struct)

            if p2 != struct_size & struct_size < 1500:
                debug.debug('size error')
                debug.debug(struct_size)
                debug.debug(p2)
                
            if struct_size == task_space.profile.get_obj_size(self.magic_struct):
                found = True
                self.params['config_key'] = config_key
                self.params['decoded_magic'] = decoded_magic
                break

            offset += 1            
        
        return found         
      
    def calculate(self):     
        """ Analyze zbot process """       
    
        addr_space = utils.load_as(self._config)

#         if not self.is_valid_profile(addr_space.profile):
#             debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources = self.signatures)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            task_space = task.get_process_address_space()

            # We must have a process AS
            if not task_space:
                continue 

            for vad, process_space in task.get_vads(): 
            
                if obj.Object("_IMAGE_DOS_HEADER", offset = vad.Start, 
                        vm = process_space).e_magic != 0x5A4D:
                    continue
                    
                data = process_space.zread(vad.Start, vad.Length)
            
                # check for the signature with YARA, both hits must be present
                matches = rules.match(data = data)

                if len(matches) < 2:
                    continue

                try:
                    dos_header = obj.Object("_IMAGE_DOS_HEADER", 
                                    offset = vad.Start, vm = task_space)
                    nt_header = dos_header.get_nt_header()
                except (ValueError, exceptions.SanityCheckException):
                    continue 

                # There must be more than 2 sections 
                if nt_header.FileHeader.NumberOfSections < 2:
                    continue

                # Get the last PE section's data 
                sections = list(nt_header.get_sections(False))
                last_sec = sections[-1]
                last_sec_data = task_space.zread(
                                    (last_sec.VirtualAddress + vad.Start), 
                                    last_sec.Misc.VirtualSize
                                    )
                # CITADEL
                if self.zbot == 'CITADEL':
                    success = self.check_matches_citadel(task_space, vad, matches, 
                                            last_sec_data)
                    if not success:                    
                        continue                 
                    success = self.scan_key_citadel(task_space)                                
                    if not success:                    
                        continue
                # ZEUS v2 or ICE IX
                elif  self.zbot == 'ZEUS':
                    success = self.check_matches_zeus2(task_space, vad, matches, 
                                                last_sec_data)
                    if not success:
                        continue                         
                    success = self.scan_key_zeus2(task_space)    
                    if not success:
                        # Check ICEIX
                        if self.zbotversion == ' 2.1.0.1':
                            self.zbot = "ICEIX"
                            self.zbotversion = ''                            
                            debug.debug('Checking ICE IX')
                            malware = ICEIX(self._config, self.filter_tasks) 
                            return malware.calculate(task, vad.Start, data, vad, task_space)
                        continue      
                                                          
                return task, vad, self.params                

    def render_text(self, outfd, data):
        """Render the plugin's default text output"""         
                
        debug.debug(self.params)    
        
        # Check for data
        if data:                            
            task, vad, params = data
                            
            # Get a magic object from the buffer
            buffer_space = addrspace.BufferAddressSpace(
                                config = self._config, 
                                data = params['decoded_magic'])
    
            magic_obj = obj.Object(self.magic_struct, 
                                offset = 0, vm = buffer_space)                        
    
            outfd.write("*" * 50 + "\n")
            outfd.write("{0:<30} : {1}\n".format("ZBot", self.zbot + self.zbotversion))
            outfd.write("{0:<30} : {1}\n".format("Process", task.ImageFileName))
            outfd.write("{0:<30} : {1}\n".format("Pid", task.UniqueProcessId))
            outfd.write("{0:<30} : {1}\n".format("Address", vad.Start))
    
            # grab the URLs from the decoded buffer
            decoded_config = params['decoded_config']
            urls = []
            while "http" in decoded_config:
                url = decoded_config[decoded_config.find("http"):]
                urls.append(url[:url.find('\x00')])
                decoded_config = url[url.find('\x00'):]
            for i, url in enumerate(urls):
                outfd.write("{0:<30} : {1}\n".format("URL {0}".format(i), url))
    
            outfd.write("{0:<30} : {1}\n".format("Identifier", 
                ''.join([chr(c) for c in magic_obj.guid if c != 0])))
            outfd.write("{0:<30} : {1}\n".format("Mutant key", magic_obj.guid_xor_key))
            outfd.write("{0:<30} : {1}\n".format("XOR key", magic_obj.xorkey))
            outfd.write("{0:<30} : {1}\n".format("Registry", 
                "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\{0}".format(magic_obj.keyname)))
            outfd.write("{0:<30} : {1}\n".format(" Value 1", magic_obj.value1))
            outfd.write("{0:<30} : {1}\n".format(" Value 2", magic_obj.value2))
            outfd.write("{0:<30} : {1}\n".format(" Value 3", magic_obj.value3))
            outfd.write("{0:<30} : {1}\n".format("Executable", magic_obj.exefile))
            outfd.write("{0:<30} : {1}\n".format("Data file", magic_obj.datfile))
    
            outfd.write("{0:<30} : \n{1}\n".format("Config RC4 key", 
                    "\n".join(
                    ["{0:#010x}  {1:<48}  {2}".format(vad.Start + o, h, ''.join(c))
                    for o, h, c in utils.Hexdump(params['config_key'])
                    ])))
            
            rc4_offset = task.obj_vm.profile.get_obj_offset(self.magic_struct, 'rc4key')
            creds_key = params['decoded_magic'][rc4_offset:rc4_offset + RC4_KEYSIZE]
    
            outfd.write("{0:<30} : \n{1}\n".format("Credential RC4 key", 
                    "\n".join(
                    ["{0:#010x}  {1:<48}  {2}".format(vad.Start + o, h, ''.join(c))
                    for o, h, c in utils.Hexdump(creds_key)
                    ])))


class Citadel(ZbotCommon):       
    """ Scanner for Citadel version """
                
    def __init__(self, config, filter_tasks):
        self.zbot = 'CITADEL'
        self.zbotversion = ' 1.3.5.1'
        self.magic_struct = ''
        self._config = config
        self.filter_tasks = filter_tasks
        self.signatures = {
            'namespace1':'rule z1 {strings: $a = {8B EC 83 EC 0C 8A 82 ?? ?? ?? ?? 88 45 FE 8A 82 01 01 00 00 88 45 FD 8A 82 02 01 00 00 B9 ?? ?? ?? ?? 88 45 FF E8 ?? ?? ?? ??} condition: $a}',
            'namespace2':'rule z2 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 03 0D ?? ?? ?? ?? 8B F2 2B C8} condition: $a}',
            'namespace3':'rule z3 {strings: $a = {68 ?? ?? 00 00 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? B8 ?? ?? 00 00 50 68 ?? ?? ?? ??} condition: $a}',
            'namespace4':'rule z4 {strings: $a = {68 ?? ?? 00 00 8D 84 24 ?? ?? ?? ?? 50 8D 44 24 ?? 50 E8 ?? ?? ?? ?? B8 ?? ?? 00 00 50 68 ?? ?? ?? ??} condition: $a}',
            'namespace5':'rule z5 {strings: $a = {81 30 ?? ?? ?? ?? 0F B6 50 03 0F B6 78 02 81 70 04 ?? ?? ?? ?? 81 70 08 ?? ?? ?? ?? 81 70 0c ?? ?? ?? ?? C1 E2 08 0B D7} condition: $a}',
            'namespace6':'rule z6 {strings: $a = {33 F6 C7 45 ?? ?? ?? ?? ?? 5B 8A 4C 3D ?? 8A D1 80 E2 07 C0 E9 03 47 83 FF 04} condition: $a}'            
        }           
                     
    def rc4_init_cit(self, key, magicKey):
        """ Initialize the RC4 keystate """
        
        hash = []
        box = []
        keyLength = len(key)
        magicKeyLen = len(magicKey)
        
        for i in range(0, 256):
            hash.append(ord(key[i % keyLength]))
            box.append(i)
        
        y = 0
        for i in range(0, 256):
            y = (y + box[i] + hash[i]) % 256
            tmp = box[i]
            box[i] = box[y]
            box[y] = tmp;

        y= 0
        for i in range(0, 256):
            magicKeyPart1 = ord(magicKey[y])  & 0x07;
            magicKeyPart2 = ord(magicKey[y]) >> 0x03;
            y += 1
            if (y == magicKeyLen):
                y = 0
            
            if (magicKeyPart1 == 0):
                box[i] = ~box[i]
            elif (magicKeyPart1 == 1):
                box[i] ^= magicKeyPart2
            elif (magicKeyPart1 == 2):
                box[i] += magicKeyPart2
            elif (magicKeyPart1 == 3):
                box[i] -= magicKeyPart2
            elif (magicKeyPart1 == 4):
                box[i] = box[i] >> (magicKeyPart2 % 8) | (box[i] << (8 - (magicKeyPart2 % 8)))
            elif (magicKeyPart1 == 5):
                box[i] = box[i] << (magicKeyPart2 % 8) | (box[i] >> (8 - (magicKeyPart2 % 8)))
            elif (magicKeyPart1 == 6):
                box[i] += 1
            elif (magicKeyPart1 == 7):
                box[i] -= 1
            
            box[i] = box[i]  & 0xff

        return ''.join([chr(c) for c in box])
    
    def calculate(self):
        # Get the addr space
        addr_space = utils.load_as(self._config)

        # cycle the processes
        for p in self.filter_tasks(tasks.pslist(addr_space)):

            # get the process address space
            ps_ad = p.get_process_address_space()
            if ps_ad == None:
                continue

            # Compile yara rules
            rules  = yara.compile(sources = self.signatures)

            # traverse the VAD
            for vad, process_space in p.get_vads():
                
                # Check for valid VAD
                if vad == None:
                    continue
                 
                # Check for PE headers at the base 
                if obj.Object("_IMAGE_DOS_HEADER", offset = vad.Start, 
                        vm = process_space).e_magic != 0x5A4D:
                    continue

                # find the start, end range and data
                start = vad.StartingVpn << 12
                end   = ((vad.EndingVpn + 1) << 12) - 1                
                data = process_space.zread(start, vad.Length)

                # check for the signature with YARA, both hits must be present
                matches = rules.match(data=data)

                if len(matches) != 5:
                    continue

                # get the NT header
                dos_header = obj.Object("_IMAGE_DOS_HEADER", start, ps_ad)
                nt_header = dos_header.get_nt_header()

                # there must be more than 2 sections 
                if nt_header.FileHeader.NumberOfSections < 2:
                    continue

                # get the last PE section's data 
                sections = list(nt_header.get_sections(unsafe=False))
                
                last_sec = sections[-1]
                last_sec_data = ps_ad.read((last_sec.VirtualAddress + start), last_sec.Misc.VirtualSize)
                if len(last_sec_data) == 0:
                    continue

                # contains C2 URL, RC4 key for decoding local.ds and the magic buffer
                decoded_config = ''
                # contains hw lock info, the user.ds RC4 key, and XOR key
                encoded_magic  = ''
                # contains BO_LOGIN_KEY
                longinKey = ''
                # contains de AES XOR key
                aes_xor_key = ''
                # Length of the Zeus Magic Object
                zeus_magic = ''
                # contains Salt RC4 Init key
                salt_rc4_initKey = ''
                
                for match in matches:
                    sigaddr = (match.strings[0][0] + start)
                    debug.debug('Found {0} at {1:#x}'.format(match.rule, sigaddr))

                    if match.rule == 'z1':
                        loginKey = ps_ad.read(
                            obj.Object('unsigned long', offset = sigaddr + 30, vm = ps_ad),0x20)
                    elif match.rule == 'z2':
                        encoded_config = ps_ad.read(
                            obj.Object('unsigned long', offset = sigaddr + 8, vm = ps_ad),
                            obj.Object('unsigned long', offset = sigaddr + 2, vm = ps_ad))
                        decoded_config = self.decode_config(encoded_config, last_sec_data)
                    elif match.rule == 'z3':
                        zeus_magic = ps_ad.read(sigaddr + 25,0x4)
                        (zeus_magic,) = struct.unpack("=I", zeus_magic[0:4])
                        encoded_magic = ps_ad.read(
                            obj.Object('unsigned long', offset = sigaddr + 31, vm = ps_ad),zeus_magic)
                    elif match.rule == 'z4':
                        zeus_magic = ps_ad.read(sigaddr + 24,0x4)
                        (zeus_magic,) = struct.unpack("=I", zeus_magic[0:4])
                        encoded_magic = ps_ad.read(
                            obj.Object('unsigned long', offset = sigaddr + 30, vm = ps_ad),zeus_magic)
                    elif match.rule == 'z5':
                        aes_xor_key = ps_ad.read(sigaddr + 2,0x4)
                        aes_xor_key += ps_ad.read(sigaddr + 17,0x4)
                        aes_xor_key += ps_ad.read(sigaddr + 24,0x4)
                        aes_xor_key += ps_ad.read(sigaddr + 31,0x4)
                    elif match.rule == 'z6':
                        salt_rc4_initKey = ps_ad.read(sigaddr + 5,0x4)
                                    
                if not decoded_config or not encoded_magic:
                    continue

                debug.debug("encoded_config:\n{0}\n".format(self.get_hex(encoded_config)))
                debug.debug("decoded_config:\n{0}\n".format(self.get_hex(decoded_config)))
                debug.debug("encoded_magic:\n{0}\n".format(self.get_hex(encoded_magic)))                
                    
                offset = 0 

                decoded_magic = ''
                config_key = ''
                aes_key = ''
                rc4_comKey = ''

                found = False

                while offset < len(decoded_config) - RC4_KEYSIZE:
                    
                    config_key = decoded_config[offset:offset+RC4_KEYSIZE]
                    decoded_magic = self.rc4(config_key, encoded_magic, loginKey)

                    # when the first four bytes of the decoded magic buffer equal the size
                    # of the magic buffer, then we've found a winning RC4 key
                    (struct_size,) = struct.unpack("=I", decoded_magic[0:4])

                    if struct_size == process_space.profile.get_obj_size('_CITADEL1345_CONFIG'):
                        self.magic_struct = '_CITADEL1345_CONFIG'
                        self.zbotversion = ' 1.3.4.5'
                        found = True
                    
                    if struct_size == process_space.profile.get_obj_size('_CITADEL1351_CONFIG'):
                        self.magic_struct = '_CITADEL1351_CONFIG'
                        self.zbotversion = ' 1.3.5.1'
                        found = True
                    
                    if found:
                        aes_key = self.rc4(config_key,hashlib.md5(loginKey).digest(),loginKey)  
                        rc4_comKey = self.rc4_init_cit(aes_key,salt_rc4_initKey)         
                        break

                    offset += 1

                if not found:
                    debug.debug('Error, cannot decode magic')
                    continue
                
                debug.debug("decoded_magic:\n{0}\n".format(self.get_hex(decoded_magic)))
                debug.debug("config_key:\n{0}\n".format(self.get_hex(config_key)))

                # grab the URLs from the decoded buffer
                urls = []
                while "http" in decoded_config:
                    url = decoded_config[decoded_config.find("http"):]
                    urls.append(url[:url.find('\x00')])
                    decoded_config = url[url.find('\x00'):]                
                
                return p, start, urls, config_key, decoded_config, decoded_magic, loginKey, aes_key, aes_xor_key, rc4_comKey
    
    def render_text(self, outfd, data):

        if data:        
            p, start, urls, config_key, decoded_config, decoded_magic, loginKey, aes_key, aes_xor_key, rc4_comKey = data

            # get a magic object from the buffer
            buffer_space = addrspace.BufferAddressSpace(config=self._config, data=decoded_magic)            
            magic_obj = obj.Object(self.magic_struct, offset = 0, vm = buffer_space)

            # Format the output
            outfd.write("*" * 80 + "\n")
            outfd.write("{0:<20} : {1}\n".format("ZBot", self.zbot + self.zbotversion))
            outfd.write("{0:<20} : {1}\n".format("Process", p.ImageFileName))
            outfd.write("{0:<20} : {1}\n".format("Pid", p.UniqueProcessId))
            outfd.write("{0:<20} : {1}\n".format("Address", start))
            number = 1
            for url in urls:
                outfd.write("{0:<20} : {1}\n".format("URL" + str(number), url))                
                number += 1
            outfd.write("{0:<20} : {1}\n".format("Identifier", ''.join([chr(c) for c in magic_obj.guid if c != 0])))
            outfd.write("{0:<20} : {1}\n".format("Mutant key", magic_obj.guid_xor_key))
            outfd.write("{0:<20} : {1}\n".format("XOR key", magic_obj.xorkey))
            outfd.write("{0:<20} : {1}\n".format("Registry", "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\{0}".format(magic_obj.keyname)))
            outfd.write("{0:<20} : {1}\n".format("  Value 1", magic_obj.value1))
            outfd.write("{0:<20} : {1}\n".format("  Value 2", magic_obj.value2))
            outfd.write("{0:<20} : {1}\n".format("  Value 3", magic_obj.value3))
            outfd.write("{0:<20} : {1}\n".format("Executable", magic_obj.exefile))
            outfd.write("{0:<20} : {1}\n".format("Login Key", loginKey.upper()))
            outfd.write("{0:<20} : {1}\n".format("AES Key", self.get_only_hex(aes_key).upper()))
            outfd.write("{0:<20} : {1}\n".format("AES XOR Key", self.get_only_hex(aes_xor_key).upper()))
            outfd.write("{0}:\n{1}\n".format("Config RC4 Key", self.get_hex(config_key[:0x100])))
            outfd.write("{0}:\n{1}\n".format("Communication RC4 Key", self.get_hex(rc4_comKey)))                        

 
class ICEIX(ZbotCommon):
    """ Scanner for ICE IX """
    
    def __init__(self, config, filter_tasks):
        self.zbot = 'ICEIX'
        self.zbotversion = '' 
        self._config = config
        self.filter_tasks = filter_tasks
        self.signatures = {
            'namespace1':'rule z1 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B 0D ?? ?? ?? ??} condition: $a}',
            'namespace5':'rule z5 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 03 0D ?? ?? ?? ??} condition: $a}',
            'namespace2':'rule z2 {strings: $a = {55 8B EC 51 A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 56 8D 34 01 A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ??} condition: $a}',
            'namespace3':'rule z3 {strings: $a = {68 02 01 00 00 8D 84 24 ?? ?? ?? ?? 50 8D 44 24 ?? 50 E8 ?? ?? ?? ?? B8 E6 01 00 00 50 68 ?? ?? ?? ??} condition: $a}',
            'namespace4':'rule z4 {strings: $a = {68 02 01 00 00 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? B8 E6 01 00 00 50 68 ?? ?? ?? ??} condition: $a}'
        }    

        self.magic_struct = '_ZEUS2_CONFIG'    

    def rc4(self, key, data, offset1=3, offset2=7):
        """ Perform a basic RC4 operation """
        state = range(256)
        x = 0 
        y = 0

        for i in range(256):
            state[i] = ord(key[i])
     
        out = [None] * len(data)

        for i in xrange(len(data)):
            x = (x + offset1) & 0xFF
            y = (state[x] + y + offset2) & 0xFF
            state[x], state[y] = state[y], state[x]
            out[i] = chr((ord(data[i]) ^ state[(state[x] + state[y]) & 0xFF]))

        return ''.join(out)

    def calculate(self, p, start, data, vad, ps_ad):
        
        addr_space = utils.load_as(self._config)
        
        # check for the signature with YARA, both hits must be present
        rules  = yara.compile(sources = self.signatures)
        matches = rules.match(data=data)

        # get the last PE section's data
        dos_header = obj.Object("_IMAGE_DOS_HEADER", start, ps_ad)
        nt_header = dos_header.get_nt_header()         
        sections = list(nt_header.get_sections(unsafe=False))
        
        last_sec = sections[-1]
        last_sec_data = ps_ad.read((last_sec.VirtualAddress + start), last_sec.Misc.VirtualSize)

        # contains C2 URL, RC4 key for decoding local.ds and the magic buffer
        decoded_config = ''
        # contains hw lock info, the user.ds RC4 key, and XOR key
        encoded_magic  = ''

        for match in matches:
            sigaddr = (match.strings[0][0] + start)
            debug.debug('Found {0} at {1:#x}'.format(match.rule, sigaddr))
            if match.rule == 'z1':
                encoded_config = ps_ad.read(
                    obj.Object('unsigned long', offset = sigaddr + 8, vm = ps_ad),
                    obj.Object('unsigned long', offset = sigaddr + 2, vm = ps_ad))
                decoded_config = self.decode_config(encoded_config, last_sec_data)
            elif match.rule == 'z2':
                config_ptr = obj.Object('unsigned long', offset = sigaddr + 26, vm = ps_ad)
                config_ptr = obj.Object('unsigned long', offset = config_ptr, vm = ps_ad)
                encoded_config = ps_ad.read(config_ptr, 0x3c8)
                decoded_config = self.rc4(self.rc4_init(encoded_config), last_sec_data[2:])
            elif match.rule == 'z5':
                encoded_config = ps_ad.read(
                    obj.Object('unsigned long', offset = sigaddr + 8, vm = ps_ad),
                    obj.Object('unsigned long', offset = sigaddr + 2, vm = ps_ad))
                decoded_config = self.decode_config(encoded_config, last_sec_data)
            elif match.rule == 'z3':
                encoded_magic = ps_ad.read(
                    obj.Object('unsigned long', offset = sigaddr + 30, vm = ps_ad),
                    addr_space.profile.get_obj_size('_ZEUS2_CONFIG'))
            elif match.rule == 'z4':
                encoded_magic = ps_ad.read(
                    obj.Object('unsigned long', offset = sigaddr + 31, vm = ps_ad),
                    addr_space.profile.get_obj_size('_ZEUS2_CONFIG'))

        if not decoded_config or not encoded_magic:
            return None

        debug.debug("encoded_config:\n{0}\n".format(self.get_hex(encoded_config)))
        debug.debug("decoded_config:\n{0}\n".format(self.get_hex(decoded_config)))
        debug.debug("encoded_magic:\n{0}\n".format(self.get_hex(encoded_magic)))

        offset = 0 

        decoded_magic = ''
        config_key = ''

        found = False

        while offset < len(decoded_config) - RC4_KEYSIZE:

            config_key = decoded_config[offset:offset+RC4_KEYSIZE]
            decoded_magic = self.rc4(config_key, encoded_magic)

            # when the first four bytes of the decoded magic buffer equal the size
            # of the magic buffer, then we've found a winning RC4 key
            (struct_size,) = struct.unpack("=I", decoded_magic[0:4])

            if struct_size == addr_space.profile.get_obj_size('_ZEUS2_CONFIG'):
                found = True
                break

            offset += 1

        if not found:
            debug.debug('Error, cannot decode magic')
            return None

        debug.debug("decoded_magic:\n{0}\n".format(self.get_hex(decoded_magic)))
        debug.debug("config_key:\n{0}\n".format(self.get_hex(config_key)))

        # grab the URL from the decoded buffer
        url = decoded_config[decoded_config.find("http"):]
        url = url[:url.find('\x00')]

        # report what we've found
        rc4_offset = addr_space.profile.get_obj_offset('_ZEUS2_CONFIG', 'rc4key')
        creds_key  = decoded_magic[rc4_offset:rc4_offset + RC4_KEYSIZE]
        return p, start, url, config_key, creds_key, decoded_config, decoded_magic
        
    def render_text(self, outfd, data):
        if data: 
            p, start, url, config_key, creds_key, decoded_config, decoded_magic = data

            # get a magic object from the buffer
            buffer_space = addrspace.BufferAddressSpace(config=self._config, data=decoded_magic)            
            magic_obj = obj.Object('_ZEUS2_CONFIG', offset = 0, vm = buffer_space)

            # Format the output
            outfd.write("*" * 80 + "\n")
            outfd.write("{0:<20} : {1}\n".format("ZBot", self.zbot + self.zbotversion))
            outfd.write("{0:<20} : {1}\n".format("Process", p.ImageFileName))
            outfd.write("{0:<20} : {1}\n".format("Pid", p.UniqueProcessId))
            outfd.write("{0:<20} : {1}\n".format("Address", start))
            outfd.write("{0:<20} : {1}\n".format("URL", url))                
            outfd.write("{0:<20} : {1}\n".format("Identifier", ''.join([chr(c) for c in magic_obj.guid if c != 0])))
            outfd.write("{0:<20} : {1}\n".format("Mutant key", magic_obj.guid_xor_key))
            outfd.write("{0:<20} : {1}\n".format("XOR key", magic_obj.xorkey))
            outfd.write("{0:<20} : {1}\n".format("Registry", "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\{0}".format(magic_obj.keyname)))
            outfd.write("{0:<20} : {1}\n".format("  Value 1", magic_obj.value1))
            outfd.write("{0:<20} : {1}\n".format("  Value 2", magic_obj.value2))
            outfd.write("{0:<20} : {1}\n".format("  Value 3", magic_obj.value3))
            outfd.write("{0:<20} : {1}\n".format("Executable", magic_obj.exefile))
            outfd.write("{0:<20} : {1}.dat\n".format("Data file", magic_obj.datfile))                        
            outfd.write("{0}:\n{1}\n".format("Config RC4 Key", self.get_hex(config_key[:0x100])))
            outfd.write("{0}:\n{1}\n".format("Credential RC4 Key", self.get_hex(creds_key[:0x100])))                        




