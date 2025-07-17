[BITS 32]
EXTERN scrollup, print
GLOBAL _start
_start:
    mov  eax, msg
    push eax
    call print
    pop  eax
    mov  eax, msg2
    push eax
    call print
    pop  eax
    mov  eax, 2
    push eax
    call scrollup
end:
    jmp end
msg  db 'Primer mensaje desde C', 10, 0
msg2 db 'Segundo mensaje desde C', 10, 0
