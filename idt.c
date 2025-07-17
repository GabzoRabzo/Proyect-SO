#include "types.h"
#include "lib.h"
#define IDT
#include "idt.h"

/*
 * 'init_idt_desc' inicializa un descriptor de interrupción
 * 'desc' es la dirección del descriptor a inicializar
 */
void init_idt_desc(u16 select, u32 offset, u16 type, struct idtdesc *desc)
{
    desc->offset0_15 = (offset & 0xffff);
    desc->select = select;
    desc->type = type;
    desc->offset16_31 = (offset & 0xffff0000) >> 16;
    return;
}

/*
 * Esta función inicializa la IDT después de que el kernel sea cargado
 * en memoria.
 */
void init_idt(void)
{
    int i;
    
    /* inicialización de la estructura para IDTR */
    kidtr.limite = IDTSIZE * 8;
    kidtr.base = IDTBASE;
    
    /* inicialización de la IDT con la rutina por defecto */
    for (i = 0; i < IDTSIZE; i++)
        init_idt_desc(0x08, (u32)_asm_default_int, 0x8E00, &kidt[i]);
    
    /* Interrupciones específicas */
    init_idt_desc(0x08, (u32)_asm_irq_0, 0x8E00, &kidt[32]);     /* IRQ0 - reloj */
    init_idt_desc(0x08, (u32)_asm_irq_1, 0x8E00, &kidt[33]);     /* IRQ1 - teclado */
    
    /* Excepciones del procesador */
    init_idt_desc(0x08, (u32)_asm_exc_GP, 0x8E00, &kidt[13]);    /* General Protection Fault */
    init_idt_desc(0x08, (u32)_asm_exc_PF, 0x8E00, &kidt[14]);    /* Page Fault */
    
    /* Llamadas al sistema - int 0x30 (TrapGate con DPL=3) */
    init_idt_desc(0x08, (u32)_asm_syscalls, 0xEF00, &kidt[0x30]);
    
    /* copia de la IDT a su dirección */
    memcpy((char *) kidtr.base, (char *) kidt, kidtr.limite);
    
    /* carga del registro IDTR */
    asm("lidtl (kidtr)");
}
