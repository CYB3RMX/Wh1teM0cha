# Wh1teM0cha: A Python Module for Mach-O Binary Parsing & Reverse Engineering
# AUTHOR: Mehmet Ali Kerimoğlu @CYB3RMX / https://github.com/CYB3RMX
# References => https://en.wikipedia.org/wiki/Mach-O
#            => https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h
#            => https://github.com/aidansteele/osx-abi-macho-file-format-reference

import re
import struct
import hashlib
import binascii
import lxml.etree as ET

# Header => first 4 bytes
header_dict = {
    b"cffaedfe": "64",
    b"cefaedfe": "32",
    b"cafebabe": "multi"
}

# CPU Type => 5th byte
cpu_type_dict = {
    b"01": "VAX",
    b"02": "ROMP",
    b"04": "NS32032",
    b"05": "NS32332",
    b"06": "MC680x0",
    b"07": "X86",
    b"08": "MIPS",
    b"09": "NS32352",
    b"0a": "MC98000",
    b"0b": "HP-PA",
    b"0c": "ARM",
    b"0d": "MC88000",
    b"0e": "SPARC",
    b"11": "RS/6000",
    b"12": "PowerPC"
}

# File Type => Offset 0xC 13th byte
file_type_dict = {
    b"01": "relocatable object file",
    b"02": "demand paged executable file",
    b"03": "fixed VM shared library file",
    b"04": "core file",
    b"05": "preloaded executable file",
    b"06": "dynamically bound shared library file",
    b"07": "dynamic link editor",
    b"08": "dynamically bound bundle file",
    b"09": "shared library stub for static linking only, no section contents",
    b"0a": "companion file with only debug sections",
    b"0b": "x86_64 kexts",
    b"0c": "a file composed of other Mach-Os to be run in the same userspace sharing a single linkedit"
}

class Wh1teM0cha:
    def __init__(self, target_binary):
        self._target_binary = target_binary
        self._target_binary_buffer = open(self._target_binary, "rb").read()
        self._fhandler = open(self._target_binary, "rb")
        self._length_of_binary = len(self._target_binary_buffer)
        self._binary_info = {
            "magic": "", "arch": "", "cpu_type": "", "file_type": "",
            "number_of_load_commands": None, "size_of_load_commands": None,
            "sha256": "", "binary_size_bytes": self._length_of_binary
        }
        self._segment_list = []
        self._section_list = []
        self._dylib_list = []
        self._weak_dylib_list = []
        self._extracted_strings = []

    def _check_header_existence(self):
        read_buff = binascii.hexlify(self._target_binary_buffer[:4])
        for sig in header_dict:
            if sig == read_buff:
                # Multi-arch handling
                if sig == b"cafebabe":
                    self._binary_info["arch"] = "multi"
                    next_headers_list = []
                    next_header = re.finditer(b'\xcf\xfa\xed\xfe', self._target_binary_buffer) # Find "cf fa ed fe"
                    for hdr in next_header:
                        next_headers_list.append(hdr.start())

                    if next_headers_list:
                        self._binary_info["magic"] = [sig, b"cffaedfe"]
                        self._fhandler.seek(next_headers_list[0])
                        buffer = self._fhandler.read(32)

                        # Get cputype
                        tmp1 = binascii.hexlify(buffer)[8:16]
                        lend = struct.pack("<I", int(tmp1, 16))
                        if lend == b"\x01\x00\x00\x07":
                            self._binary_info["cpu_type"] = "X86_64"

                        # Get filetype
                        tmp1 = binascii.hexlify(buffer)[24:26]
                        self._pattern_search(buffer=tmp1, target_pattern_dict=file_type_dict, key="file_type")

                        # Number of load commands
                        tmp1 = binascii.hexlify(buffer)[32:40]
                        self._binary_info["number_of_load_commands"] = binascii.hexlify(struct.pack("<I", int(tmp1, 16)))

                        # Size of load commands
                        tmp1 = binascii.hexlify(buffer)[40:48]
                        self._binary_info["size_of_load_commands"] = binascii.hexlify(struct.pack("<I", int(tmp1, 16)))
                        return True
                else:
                    self._binary_info["magic"] = sig.decode()
                    # Arch
                    read_buff = binascii.hexlify(self._target_binary_buffer[:4])
                    self._pattern_search(buffer=read_buff, target_pattern_dict=header_dict, key="arch")

                    # CPU TYPE
                    read_buff = binascii.hexlify(self._target_binary_buffer[4:5])
                    self._pattern_search(buffer=read_buff, target_pattern_dict=cpu_type_dict, key="cpu_type")
                    return True
        return False

    def _pattern_search(self, buffer, target_pattern_dict, key):
        for sig in target_pattern_dict:
            if sig == buffer:
                self._binary_info[key] = target_pattern_dict[sig]
                break

    def _commands_parser_number_of(self, buffer):
        # Calculate => number_of_load_commands
        self._binary_info["number_of_load_commands"] = int(b"0x"+buffer, 16)

    def _commands_parser_size_of(self, buffer):
        # Calculate => size_of_load_commands
        self._binary_info["size_of_load_commands"] = int(b"0x"+buffer, 16)

    def _dictionary_parser(self, target_dict):
        tmpdct = {}
        for key in target_dict:
            if target_dict[key]["occurence"] != 0:
                tmpdct.update({key: target_dict[key]})
        return tmpdct

    def _calculate_hash_value(self):
        hash_sha256 = hashlib.sha256()
        try:
            with open(self._target_binary, "rb") as ff:
                for chunk in iter(lambda: ff.read(4096), b""):
                    hash_sha256.update(chunk)
            ff.close()
            return hash_sha256.hexdigest()
        except:
            return None

    def _section_info_helper(self, section_name):
        # We need to locate target section offset first
        if not self._section_list:
            self.get_sections()
        for sec in self._section_list:
            if sec["section_name"].decode() == section_name:
                target_section_offset = sec["offset"]
                # Now we need to read until next sections offset
                s_index = self._section_list.index(sec)
                next_section = self._section_list[s_index+1]
                break
        return [sec,next_section]

    def get_segments(self):
        """
           Description: This method is for fetch segment information from the target binary
           Usage: wm.get_segments()
        """
        if not self._segment_list:
            # Look for "__ | 5f 5f"
            header_start = []
            matches = re.finditer(r"__".encode(), self._target_binary_buffer)
            for mat in matches:
                if mat.start() not in header_start:
                    header_start.append(hex(mat.start()))

            # Check for indicators => cmd type, cmd name etc.
            for off in header_start:
                # Read cmdtype
                self._fhandler.seek(int(off, 16)-0x8)
                chk_bfr = self._fhandler.read(12)
                if binascii.hexlify(chk_bfr).decode()[:2] == "19": # if cmdtype==19 cmdtype=> segment_64
                    # Read cmdname
                    self._fhandler.seek(int(off, 16)+0x2)
                    chk_bfr = self._fhandler.read(4) 
                    # Check for uppercase letter for valid segment name
                    if chr(chk_bfr[0]).isupper():
                        # Extract segment name from binary data
                        self._fhandler.seek(int(off, 16))
                        buffer = self._fhandler.read(24) # This data should enough
                        segname = re.findall(r"[^\x00-\x1F\x7F-\xFF]{4,}".encode(), buffer)
                        if segname and segname[0].decode() not in str(self._segment_list):
                            self._segment_list.append({"segment_name": segname[0], "offset": off})
            return self._segment_list
        else:
            return self._segment_list

    def get_sections(self):
        """
            Description: This method is for fetch section information from the target binary
            Usage: wm.get_sections()
        """
        if not self._section_list:
            # Look for "__ | 5f 5f"
            header_start = []
            matches = re.finditer(r"__".encode(), self._target_binary_buffer)
            for mat in matches:
                if mat.start() not in header_start:
                    header_start.append(hex(mat.start()))

            # We also need segment names to verify sections
            if not self._segment_list:
                self.get_segments()

            for off in header_start:
                self._fhandler.seek(int(off, 16))
                buffer = self._fhandler.read(48) # This length of data should be enough
                if chr(buffer[2]).islower(): # section names starts with lowercase characters
                    secname = re.findall(r"[^\x00-\x1F\x7F-\xFF]{4,}".encode(), buffer) # extract strings
                    if secname:
                        if ((len(secname) > 1) and (secname[-1].decode() in str(self._segment_list))) and (secname[0].decode() not in str(self._section_list)): # [b'__text', b'__TEXT']
                            self._section_list.append({"section_name": secname[0], "offset": off})
                        elif (len(secname) == 1):
                            for seg in self._segment_list:
                                if (seg["segment_name"].decode() in secname[0].decode()) and (secname[0].decode() not in str(self._section_list)):
                                    self._section_list.append({"section_name": secname[0], "offset": off})
                                    break
                        else:
                            pass
            return self._section_list
        else:
            return self._section_list

    def get_dylib_names(self):
        """
            Description: This method is for extracting dylib names from the target binary
            Usage: wm.get_dylib_names()
        """
        if not self._dylib_list:
            # We need to locate cmd: 0xc (LOAD_DYLIB)
            # Hex pattern: cmd_header=>"0c000000" size=>"58000000" "1800000002000000"
            load_dylib_cmd_offset = re.finditer(b'\x0c\x00\x00\x00', self._target_binary_buffer)
            for mat in load_dylib_cmd_offset:
                self._fhandler.seek(mat.start())
                buffer = self._fhandler.read(16)
                if b"0000001800000002" in binascii.hexlify(buffer): # Verify cmd
                    # Get size
                    cmdsize = int(binascii.hexlify(buffer)[2:10], 16)

                    # Read sizeof(cmdsize) and get lib name
                    self._fhandler.seek(mat.start()) # return back to the target offset
                    dylib_buffer = self._fhandler.read(cmdsize)

                    # Timestamp extraction
                    timestamp = binascii.hexlify(dylib_buffer)[18:26]

                    # Current version extraction
                    current_version_tmp = binascii.hexlify(dylib_buffer)[32:40]
                    lend = struct.pack("<I", int(current_version_tmp, 16))
                    current_version = binascii.hexlify(lend)

                    # String extraction
                    extracted_strings = re.findall(r"[^\x00-\x1F\x7F-\xFF]{4,}".encode(), dylib_buffer)
                    if extracted_strings and extracted_strings[-1].decode() not in str(self._dylib_list):
                        self._dylib_list.append(
                            {
                                "offset": hex(mat.start()),
                                "cmd": "0xc",
                                "cmdname": "LOAD_DYLIB",
                                "cmdsize": hex(cmdsize),
                                "timestamp": timestamp,
                                "current_version": current_version,
                                "libname": extracted_strings[-1]
                            }
                        )
            return self._dylib_list
        else:
            return self._dylib_list

    def get_weak_dylib_names(self):
        """
            Description: This method is for extracting weak dylib names from the target binary
            Usage: wm.get_weak_dylib_names()
        """
        if not self._weak_dylib_list:
            # Hex pattern: cmd_header=>"80000018" size=>"58000000" "1800000002000000"
            load_weak_dylib_cmd_offset = re.finditer(b'\x18\x00\x00\x80', self._target_binary_buffer)
            for mat in load_weak_dylib_cmd_offset:
                self._fhandler.seek(mat.start())
                buffer = self._fhandler.read(16)
                if b"0000001800000002" in binascii.hexlify(buffer): # Verify cmd
                    # Get size
                    tmp1 = binascii.hexlify(buffer)[8:16]
                    lend = struct.pack("<I", int(tmp1, 16))
                    cmdsize = int(binascii.hexlify(lend), 16)

                    # Read sizeof(cmdsize) and get lib name
                    self._fhandler.seek(mat.start()) # return back to the target offset
                    dylib_buffer = self._fhandler.read(cmdsize)

                    # Timestamp extraction
                    timestamp = binascii.hexlify(dylib_buffer)[18:26]

                    # Current version extraction
                    current_version_tmp = binascii.hexlify(dylib_buffer)[32:40]
                    lend = struct.pack("<I", int(current_version_tmp, 16))
                    current_version = binascii.hexlify(lend)

                    # String extraction
                    extracted_strings = re.findall(r"[^\x00-\x1F\x7F-\xFF]{4,}".encode(), dylib_buffer)
                    if extracted_strings and extracted_strings[-1].decode() not in str(self._weak_dylib_list):
                        self._weak_dylib_list.append(
                            {
                                "offset": hex(mat.start()),
                                "cmd": "80000018",
                                "cmdname": "LOAD_WEAK_DYLIB",
                                "cmdsize": hex(cmdsize),
                                "timestamp": timestamp,
                                "current_version": current_version,
                                "libname": extracted_strings[-1]
                            }
                        )
            return self._weak_dylib_list
        else:
            return self._weak_dylib_list

    def segment_info(self, segment_name):
        """
            Description: This method is for get segment information.
            Usage: wm.segment_info(segment_name="__TEXT")
        """
        # We need to locate target segments offset first
        if not self._segment_list:
            self.get_segments()

        if segment_name not in str(self._segment_list):
            raise Exception("Segment is not found!")

        for seg in self._segment_list:
            if seg["segment_name"].decode() == segment_name:
                target_segment_offset = seg["offset"]
                break

        # Read segment data
        self._fhandler.seek(int(target_segment_offset, 16)-0x8) # locate segment_start
        segment_data = self._fhandler.read(72)

        if hex(segment_data[0]) == "0x19" and segment_data[8:10] == b"__": # Check cmd type and header start
            # Unpack the segment data using little-endian format
            cmd, cmdsize, segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack('<II16sQQQQIIII', segment_data)

            # Return value
            segment_info_dict = {
                "segment_name": segname,
                "offset": target_segment_offset,
                "cmd": hex(cmd),
                "cmdsize": hex(cmdsize),
                "vmaddr": hex(vmaddr),
                "vmsize": hex(vmsize),
                "fileoff": hex(fileoff),
                "filesize": hex(filesize),
                "maxprot": hex(maxprot),
                "initprot": hex(initprot),
                "nsects": hex(nsects)
            }
            return segment_info_dict
        else:
            raise Exception("This is not a valid segment offset!")

    def section_info(self, section_name):
        """
            Description: This method is for get section information.
            Usage: wm.section_info(section_name="__text")
        """
        # We need to locate target section offset first
        if not self._section_list:
            self.get_sections()
        for sec in self._section_list:
            if sec["section_name"].decode() == section_name:
                target_section_offset = int(sec["offset"], 16)
                # Now we need to read until next sections offset
                s_index = self._section_list.index(sec)
                next_section = self._section_list[s_index+1]
                break

        # Read between 2 secton offsets (current, next)
        self._fhandler.seek(target_section_offset)
        section_buffer = self._fhandler.read(int(next_section["offset"], 16)-target_section_offset)

        # Get segment name
        segname = re.findall(r"[^\x00-\x1F\x7F-\xFF]{4,}".encode(), section_buffer)[-1]

        # Get section offset
        tmp1 = binascii.hexlify(section_buffer)[64:72]
        lend = struct.pack("<I", int(tmp1, 16))
        section_offset = binascii.hexlify(lend)

        # Get section size
        _ = self.get_binary_info()
        if self._binary_info["arch"] != "multi":
            tmp1 = binascii.hexlify(section_buffer)[80:88]
            lend = struct.pack("<I", int(tmp1, 16))
            section_size = binascii.hexlify(lend)
        else:
            tmp1 = binascii.hexlify(section_buffer)[72:80]
            lend = struct.pack("<I", int(tmp1, 16))
            section_size = binascii.hexlify(lend)

        # Return value
        section_info_report = {
            "section_name": section_name,
            "segment_name": segname,
            "offset": section_offset,
            "size": section_size
        }
        return section_info_report

    def dump_segment(self, segment_name):
        """
            Description: This method is for dumping segment data
            Usage: wm.dump_segment(segment_name="__TEXT")
        """
        # We need segment info first
        target_segment_info = self.segment_info(segment_name=segment_name)

        # Seek target offset and read sizeof(segment)
        self._fhandler.seek(int(target_segment_info["offset"], 16)-0x8) # locate segment start
        return self._fhandler.read(int(target_segment_info["filesize"], 16))

    def dump_section(self, section_name):
        """
            Description: This method is for dumping section data
            Usage: wm.dump_section(section_name="__TEXT")
        """
        # We need section info first
        target_section_info = self.section_info(section_name=section_name)

        # Seek target offset and read sizeof(section) 
        self._fhandler.seek(int(target_section_info["offset"], 16))
        return self._fhandler.read(int(target_section_info["size"], 16))
    
    def get_strings(self):
        """
            Description: This method is for dumping string values
            Usage: wm.get_strings()
        """
        self._extracted_strings = re.findall(r"[^\x00-\x1F\x7F-\xFF]{4,}".encode(), self._target_binary_buffer)
        if self._extracted_strings:
            return self._extracted_strings
        else:
            return []

    def dump_sc_superblob(self):
        """
            Description: This method is for dumping _SC_SuperBlob
            Usage: wm.dump_sc_superblob()
        """
        header_superblob = b'\xfa\xde\x0c\xc0'

        try:
            # Find superblob header
            sb_offset = list(re.finditer(header_superblob, self._target_binary_buffer))[-1].start()

            # Get length
            self._fhandler.seek(sb_offset)
            buffer = self._fhandler.read(16)
            blob_length = binascii.hexlify(buffer)[8:16]

            # Read sizeof(blob)
            self._fhandler.seek(sb_offset)
            sc_superblob_data = self._fhandler.read(int(blob_length, 16))
            return sc_superblob_data
        except:
            raise Exception("No such load command -> _SC_SuperBlob")

    def get_plists(self):
        """
            Description: This method is for dumping .plist data from _SC_SuperBlob
            Usage: wm.get_plists()
        """
        plist_header = b"<\?xml"
        plist_footer = b"<\/plist>"

        # Dump superblob
        spblb_data = self.dump_sc_superblob()

        # Find headers first
        xmlstart = list(re.finditer(plist_header, spblb_data))

        # After that we also need to find footers as well
        xmlend = list(re.finditer(plist_footer, spblb_data))

        if (xmlstart and xmlend) and (len(xmlstart) == len(xmlend)):
            plist_array = []
            for start, end in zip(xmlstart, xmlend):
                buffer = spblb_data[start.start():end.end()].replace(b"\t", b"").replace(b"\n", b"")
                parser = ET.XMLParser(recover=True)
                tree = ET.ElementTree(ET.fromstring(buffer, parser=parser))
                plist_array.append(tree)
            return plist_array
        else:
            return []

    def code_signature_info(self):
        """
            Description: This method is for get information about code signature section
            Usage: wm.code_signature_info()
        """
        lc_code_signature_pattern = b'\x1d\x00\x00\x00\x10\x00\x00\x00'
        try:
            # Locate LC_CODE_SIGNATURE
            cs_offset = list(re.finditer(lc_code_signature_pattern, self._target_binary_buffer))[0].start()

            # Parse LC_CODE_SIGNATURE
            self._fhandler.seek(cs_offset)
            buffer = self._fhandler.read(16)

            # Get dataoff
            dataoff = binascii.hexlify(struct.pack("<I", int(binascii.hexlify(buffer)[16:24], 16)))

            # Get datasize
            datasize = binascii.hexlify(struct.pack("<I", int(binascii.hexlify(buffer)[24:32], 16)))

            # Return value
            report_cs = {"dataoff": dataoff, "datasize": datasize}
            return report_cs
        except:
            raise Exception("No such load command -> LC_CODE_SIGNATURE")

    def application_identifier(self):
        """
            Description: This method returns application identifier name (For example "com.example.app")
            Usage: wm.application_identifier()
        """
        # 1. We need to read _SC_SuperBlob
        blob_data = self.dump_sc_superblob()

        # Extract app_identifier
        app_identifier = re.findall(r"[^\x00-\x1F\x7F-\xFF]{4,}".encode(), blob_data)[0]
        return app_identifier.decode()

    def get_entrypoint(self):
        """
            Description: This method returns entrypoint offset of the target binary
            Usage: wm.get_entrypoint()
        """
        lc_main_pattern = b'\(\x00\x00\x80\x18\x00\x00\x00'
        try:
            # Locate LC_MAIN and read 16 bytes
            entry_val = list(re.finditer(lc_main_pattern, self._target_binary_buffer))[0].start()
            self._fhandler.seek(entry_val)
            buffer = binascii.hexlify(self._fhandler.read(16))

            # Parse buffer and get entryoff
            entryoff = binascii.hexlify(struct.pack("<I", int(buffer[16:24], 16)))
            return {"entryoff": entryoff}
        except:
            raise Exception("No such load command -> LC_MAIN")

    def get_dyld_info(self):
        """
            Description: This method returns information about LC_DYLD_INFO[_ONLY]
            Usage: wm.get_dyld_info()
        """
        lc_dyld_info_pattern = b'\"\x00\x00\x800\x00\x00\x00'
        try:
            # Return value
            dyld_return_value = {
                "rebase_off": None,
                "rebase_size": None,
                "bind_off": None,
                "bind_size": None,
                "weak_bind_off": None,
                "weak_bind_size": None,
                "lazy_bind_off": None,
                "lazy_bind_size": None,
                "export_off": None,
                "export_size": None
            }

            # Locate LC_DYLD_INFO[_ONLY] and read 48 bytes of data
            dyld_offset_start = list(re.finditer(lc_dyld_info_pattern, self._target_binary_buffer))[0].start()
            self._fhandler.seek(dyld_offset_start)
            buffer = binascii.hexlify(self._fhandler.read(48))

            # Parse buffer
            buffer_index = 16
            for key in dyld_return_value:
                key_val = binascii.hexlify(struct.pack("<I", int(buffer[buffer_index:buffer_index+8], 16)))
                dyld_return_value[key] = key_val
                buffer_index = buffer_index+8
                if buffer_index >= 96:
                    break
            return dyld_return_value
        except:
            raise Exception("No such load command -> LC_DYLD_INFO[_ONLY]")

    def get_symtab_info(self):
        """
            Description: This method returns information about LC_SYMTAB
            Usage: wm.get_symtab()
        """
        lc_symtab_pattern = b'\x02\x00\x00\x00\x18\x00\x00\x00'
        try:
            # Return val
            symtab_return = {
                "symoff": None,
                "nsyms": None,
                "stroff": None,
                "strsize": None
            }
            # Locate LC_SYMTAB and read 24 bytes of data
            lc_symtab_offset_start = list(re.finditer(lc_symtab_pattern, self._target_binary_buffer))[0].start()
            self._fhandler.seek(lc_symtab_offset_start)
            buffer = binascii.hexlify(self._fhandler.read(24))

            # Parse symoff
            symtab_return["symoff"] = binascii.hexlify(struct.pack("<I", int(buffer[16:24], 16)))

            # Parse nsyms
            symtab_return["nsyms"] = binascii.hexlify(struct.pack("<I", int(buffer[24:32], 16)))

            # Parse stroff
            symtab_return["stroff"] = binascii.hexlify(struct.pack("<I", int(buffer[32:40], 16)))

            # Parse strsize
            symtab_return["strsize"] = binascii.hexlify(struct.pack("<I", int(buffer[40:48], 16)))
            return symtab_return
        except:
            raise Exception("No such load command -> LC_SYMTAB")

    def dump_symtab_strings(self):
        """
            Description: This method returns string values contained in LC_SYMTAB
            Usage: wm.dump_symtab_strings()
        """
        # We need to locate offset start of the symtab strings
        sym_inf = self.get_symtab_info()

        # After that dump sizeof(symtab_strings_offset)
        self._fhandler.seek(int(sym_inf["stroff"], 16))
        buffer = self._fhandler.read(int(sym_inf["strsize"], 16))
        str_vals = re.findall(r"[^\x00-\x1F\x7F-\xFF]{4,}".encode(), buffer)

        return str_vals

    def get_dysymtab_info(self):
        """
            Description: This method returns information about LC_DYSYMTAB
            Usage: wm.get_dysymtab_info()
        """
        lc_dysymtab_pattern = b'\x0b\x00\x00\x00P\x00\x00\x00'
        try:
            # Return value
            dysymtab_return = {
                "ilocalsym": None,
                "nlocalsym": None,
                "iextdefsym": None,
                "nextdefsym": None,
                "iundefsym": None,
                "nundefsym": None,
                "tocoff": None,
                "ntoc": None,
                "modtaboff": None,
                "nmodtab": None,
                "extrefsymoff": None,
                "nextrefsyms": None,
                "indirectsymoff": None,
                "nindirectsyms": None,
                "extreloff": None,
                "nextrel": None,
                "locreloff": None,
                "nlocrel": None
            }

            # Locate LC_DYSYMTAB pattern and read 80 bytes of data
            lc_dysymtab_offset = list(re.finditer(lc_dysymtab_pattern, self._target_binary_buffer))[0].start()
            self._fhandler.seek(lc_dysymtab_offset)
            buffer = binascii.hexlify(self._fhandler.read(80))

            # Parse buffer
            buffer_index = 16
            for key in dysymtab_return:
                key_val = binascii.hexlify(struct.pack("<I", int(buffer[buffer_index:buffer_index+8], 16)))
                dysymtab_return[key] = key_val
                buffer_index = buffer_index+8
                if buffer_index >= 160:
                    break
            return dysymtab_return
        except:
            raise Exception("No such load command -> LC_DYSYMTAB")

    def get_data_in_code(self):
        """
            Description: This method returns information about LC_DATA_IN_CODE
            Usage: wm.get_data_in_code()
        """
        lc_data_in_code_pattern = b'\\)\x00\x00\x00\x10\x00\x00\x00'
        try:
            # Return value
            data_in_code_ret = {
                "dataoff": None,
                "datasize": None
            }

            # Locate LC_DATA_IN_CODE and read 16 bytes of data
            lc_data_in_code_offset = list(re.finditer(lc_data_in_code_pattern, self._target_binary_buffer))[0].start()
            self._fhandler.seek(lc_data_in_code_offset)
            buffer = binascii.hexlify(self._fhandler.read(16))

            # Parse "dataoff"
            data_in_code_ret["dataoff"] = binascii.hexlify(struct.pack("<I", int(buffer[16:24], 16)))

            # Parse "datasize"
            data_in_code_ret["datasize"] = binascii.hexlify(struct.pack("<I", int(buffer[24:32], 16)))
            return data_in_code_ret
        except:
            raise Exception("No such load command -> LC_DATA_IN_CODE")

    def get_binary_info(self):
        """
            Description: This method is for getting general information about the target binary
            Usage: wm.get_binary_info()
        """
        if self._check_header_existence():
            # File Type
            if self._binary_info["arch"] != "multi":
                read_buff = binascii.hexlify(self._target_binary_buffer[12:13])
                self._pattern_search(buffer=read_buff, target_pattern_dict=file_type_dict, key="file_type")

            # Number of load commands
            if self._binary_info["arch"] != "multi":
                read_buff = binascii.hexlify(self._target_binary_buffer[13:17])
                self._commands_parser_number_of(buffer=read_buff)

            # Size of load commands
            if self._binary_info["arch"] != "multi":
                read_buff = binascii.hexlify(self._target_binary_buffer[17:21])
                self._commands_parser_size_of(buffer=read_buff)

            # Calculate sha256
            hash_val = self._calculate_hash_value()
            self._binary_info["sha256"] = hash_val
            return self._binary_info
        else:
            raise Exception("There is no pattern about MACH-O!!")
