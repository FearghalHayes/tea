.global _start

.text
_start:
    # write(1, msg, 14)
    mov $1, %rax
    mov $1, %rdi
    lea msg(%rip), %rsi
    mov $12, %rdx
    syscall

    # exit(0)
    mov $60, %rax
    xor %rdi, %rdi
    syscall

.data
msg:
    .ascii "Hello, TEA!\n"
