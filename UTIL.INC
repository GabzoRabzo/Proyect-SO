afficher:
    push ax
    push bx
.debut:
    lodsb         ; ds:si -> al
    cmp al, 0     ; fin chaîne ?
    jz .fin
    mov ah, 0x0E  ; appel au service 0x0e, int 0x10 du bios
    mov bx, 0x07  ; bx -> attribut, al -> caractère ASCII
    int 0x10
    jmp .debut
.fin:
    pop bx
    pop ax
    ret
