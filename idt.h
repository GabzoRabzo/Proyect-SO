#ifndef IDT_H_
#define IDT_H_

#include "types.h"

#define IDTBASE    0x00000000     /* adresse de base de la IDT */
#define IDTSIZE    0xFF           /* nombre max de descripteurs dans la IDT */

/* Descriptor de interrupción */
struct idtdesc {
    u16 offset0_15;       /* offset bits 0..15 */
    u16 select;           /* selector de segmento */
    u16 type;             /* type de gate */
    u16 offset16_31;      /* offset bits 16..31 */
} __attribute__ ((packed));

/* Registro IDTR */
struct idtr {
    u16 limite;           /* limite de la IDT */
    u32 base;             /* adresse de base de la IDT */
} __attribute__ ((packed));

/* Variables globales */
#ifdef IDT
struct idtdesc kidt[IDTSIZE];     /* IDT del kernel */
struct idtr kidtr;                /* registro IDTR del kernel */
#else
extern struct idtdesc kidt[];
extern struct idtr kidtr;
#endif

/* Funciones */
void init_idt_desc(u16 select, u32 offset, u16 type, struct idtdesc *desc);
void init_idt(void);

/* Prototipos de rutinas de interrupción en ensamblador */
extern void _asm_default_int(void);
extern void _asm_irq_0(void);
extern void _asm_irq_1(void);
extern void _asm_exc_GP(void);
extern void _asm_exc_PF(void);

/* Prototipos de rutinas de llamadas al sistema */
extern void _asm_syscalls(void);

#endif
