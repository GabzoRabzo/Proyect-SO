%define BASE    0x100  ; 0x0100:0x0 = 0x1000
%define KSIZE   50     ; número de sectores a cargar (kernel más grande)
[BITS 16]
[ORG 0x0]
jmp start
%include "UTIL.INC"
start:
; initialisation des segments en 0x07C0
    mov ax, 0x07C0
    mov ds, ax
    mov es, ax
    mov ax, 0x8000    ; stack en 0xFFFF
    mov ss, ax
    mov sp, 0xf000

; récupération de l'unité de boot
    mov [bootdrv], dl    

; affiche un msg
    mov si, msgDebut
    call afficher
; charger le noyau
    xor ax, ax
    int 0x13
    push es
    mov ax, BASE
    mov es, ax
    mov bx, 0
    mov ah, 2
    mov al, KSIZE
    mov ch, 0
    mov cl, 2
    mov dh, 0
    mov dl, [bootdrv]
    int 0x13
    pop es
; initialisation du pointeur sur la GDT
    mov ax, gdtend    ; calcule la limite de GDT
    mov bx, gdt
    sub ax, bx
    mov word [gdtptr], ax
    xor eax, eax      ; calcule l'adresse linéaire de GDT
    xor ebx, ebx
    mov ax, ds
    mov ecx, eax
    shl ecx, 4
    mov bx, gdt
    add ecx, ebx
    mov dword [gdtptr+2], ecx
; passage en mode protégé
    cli                 ; désactive les interruptions
    lgdt [gdtptr]       ; charge la GDT
    mov eax, cr0
    or  ax, 1
    mov cr0, eax        ; PE mis à 1 (CR0)
    jmp next
next:
    mov ax, 0x10        ; segment de données
    mov ds, ax
    mov fs, ax
    mov gs, ax
    mov es, ax
    mov ss, ax
    mov esp, 0x9F000    ; nouvelle pile en 32 bits
    jmp dword 0x8:0x1000    ; réinitialise le segment de codev et exécute le kernel
bootdrv:  db 0
msgDebut: db "Passage en mode protege...", 13, 10, 0
; Global Descriptor Table (GDT)
gdt:
    ; Descripteur NULL (obligatoire)
    db 0, 0, 0, 0, 0, 0, 0, 0
gdt_cs:
    ; Segment de code: base=0x0, limite=0xFFFFF, 32-bit, executable
    db 0xFF, 0xFF, 0x0, 0x0, 0x0, 10011011b, 11011111b, 0x0
gdt_ds:
    ; Segment de données: base=0x0, limite=0xFFFFF, 32-bit, writable
    db 0xFF, 0xFF, 0x0, 0x0, 0x0, 10010011b, 11011111b, 0x0
gdtend:
; Pointeur vers la GDT
gdtptr:
    dw 0  ; limite
    dd 0  ; base
;; NOP jusqu'à 510
times 510-($-$$) db 144
dw 0xAA55
