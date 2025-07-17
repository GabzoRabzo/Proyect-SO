[BITS 32]

global _start, start
extern kmain

; Constantes del Multiboot
%define MULTIBOOT_HEADER_MAGIC  0x1BADB002
%define MULTIBOOT_HEADER_FLAGS  0x00000003
%define CHECKSUM -(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS)

section .text

_start:
    jmp start

; El header Multiboot debe estar en los primeros 8KB
align 4
multiboot_header:
    dd MULTIBOOT_HEADER_MAGIC
    dd MULTIBOOT_HEADER_FLAGS
    dd CHECKSUM
; ----- Fin del Multiboot Header -----

start:
    ; GRUB nos pasa información en EBX
    push ebx
    call kmain
    
    ; Si kmain retorna, detener el sistema
    cli     ; deshabilitar interrupciones
    hlt     ; detener CPU
    
    ; Bucle infinito por si acaso
.hang:
    jmp .hang
