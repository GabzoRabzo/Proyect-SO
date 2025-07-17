; interrupt.asm - Rutinas de interrupción en ensamblador
[BITS 32]

; Prototipos de funciones C
extern isr_default_int
extern isr_clock_int
extern isr_kbd_int
extern do_syscalls
extern page_fault_handler

; Macros para guardar y restaurar registros
%macro  SAVE_REGS 0
    pushad          ; Guardar todos los registros generales
    push ds
    push es
    push fs
    push gs
    push ebx
    mov bx, 0x10    ; Selector de segmento de datos del kernel
    mov ds, bx
    pop ebx
%endmacro

%macro  RESTORE_REGS 0
    pop gs
    pop fs
    pop es
    pop ds
    popad           ; Restaurar todos los registros generales
%endmacro

; Rutina de interrupción por defecto
global _asm_default_int
_asm_default_int:
    SAVE_REGS
    call isr_default_int
    RESTORE_REGS
    iret

; Rutina de interrupción para IRQ0 (timer)
global _asm_irq_0
_asm_irq_0:
    SAVE_REGS
    call isr_clock_int
    mov al, 0x20    ; EOI (End Of Interrupt)
    out 0x20, al
    RESTORE_REGS
    iret

; Rutina de interrupción para IRQ1 (teclado)
global _asm_irq_1
_asm_irq_1:
    SAVE_REGS
    call isr_kbd_int
    mov al, 0x20    ; EOI (End Of Interrupt)
    out 0x20, al
    RESTORE_REGS
    iret

; Rutina de interrupción para General Protection Fault
global _asm_exc_GP
_asm_exc_GP:
    SAVE_REGS
    call isr_default_int
    RESTORE_REGS
    add esp, 4      ; Limpiar código de error de la pila
    iret

; Rutina de interrupción para Page Fault
global _asm_exc_PF
_asm_exc_PF:
    SAVE_REGS
    call page_fault_handler
    RESTORE_REGS
    add esp, 4      ; Limpiar código de error de la pila
    iret
    
; Rutina de interrupción para llamadas al sistema (int 0x30)
global _asm_syscalls
_asm_syscalls:
    SAVE_REGS
    push eax                 ; transmission du numéro d'appel
    call do_syscalls
    pop eax
    RESTORE_REGS
    iret
