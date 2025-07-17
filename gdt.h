#ifndef _GDT_H_
#define _GDT_H_

#include "types.h"
#define GDTBASE    0x00000800     /* adresse de base de la GDT */
#define GDTSIZE    0xFF           /* nombre max de descripteurs dans la GDT */

/* Descripteur de segment */
struct gdtdesc {
    u16 lim0_15;      /* limite bits 0..15 */
    u16 base0_15;     /* base bits 0..15 */
    u8 base16_23;     /* base bits 16..23 */
    u8 acces;         /* byte de acceso */
    u8 lim16_19 : 4;  /* limite bits 16..19 */
    u8 other : 4;     /* otros flags */
    u8 base24_31;     /* base bits 24..31 */
} __attribute__ ((packed));

/* Registre GDTR */
struct gdtr {
    u16 limite;       /* limite de la GDT */
    u32 base;         /* adresse de base de la GDT */
} __attribute__ ((packed));

/* Variables globales */
#ifdef __GDT__
struct gdtdesc kgdt[GDTSIZE];     /* GDT del kernel */
struct gdtr kgdtr;                /* registro GDTR del kernel */
#else
extern struct gdtdesc kgdt[];
extern struct gdtr kgdtr;
#endif

/* Funciones */
void init_gdt_desc(u32 base, u32 limite, u8 acces, u8 other, struct gdtdesc *desc);
void init_gdt(void);

#endif
