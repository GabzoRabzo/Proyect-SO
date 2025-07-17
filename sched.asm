global do_switch

do_switch:
    ; Recuperar la dirección de *current
    mov esi, [esp]
    pop eax                 ; desapilar @current

    ; Preparar los registros del nuevo proceso
    push dword [esi+4]      ; eax
    push dword [esi+8]      ; ecx
    push dword [esi+12]     ; edx
    push dword [esi+16]     ; ebx
    push dword [esi+24]     ; ebp
    push dword [esi+28]     ; esi
    push dword [esi+32]     ; edi
    push dword [esi+48]     ; ds
    push dword [esi+50]     ; es
    push dword [esi+52]     ; fs
    push dword [esi+54]     ; gs

    ; Quitar el mask del PIC
    mov al, 0x20
    out 0x20, al

    ; Cargar tabla de páginas
    mov eax, [esi+56]
    mov cr3, eax

    ; Cargar los registros
    pop gs
    pop fs
    pop es
    pop ds
    pop edi
    pop esi
    pop ebp
    pop ebx
    pop edx
    pop ecx
    pop eax

    ; Retornar (conmutar al nuevo proceso)
    iret
