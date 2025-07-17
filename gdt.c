#include "types.h"
#include "lib.h"

#define __GDT__
#include "gdt.h"

/*
 * 'init_gdt_desc' inicializa un descriptor de segmento situado en gdt o en ldt.
 * 'desc' es la dirección lineal del descriptor a inicializar.
 */
void init_gdt_desc(u32 base, u32 limite, u8 acces, u8 other,
                   struct gdtdesc *desc)
{
    desc->lim0_15 = (limite & 0xffff);
    desc->base0_15 = (base & 0xffff);
    desc->base16_23 = (base & 0xff0000) >> 16;
    desc->acces = acces;
    desc->lim16_19 = (limite & 0xf0000) >> 16;
    desc->other = (other & 0xf);
    desc->base24_31 = (base & 0xff000000) >> 24;
    return;
}

/*
 * Esta función inicializa la GDT después de que el kernel sea cargado
 * en memoria. Una GDT ya está operativa, pero es la que fue
 * inicializada por el sector de boot y que no corresponde
 * necesariamente a la que queremos.
 */
void init_gdt(void)
{
    /* inicialización de los descriptores de segmento */
    init_gdt_desc(0x0, 0x0, 0x0, 0x0, &kgdt[0]);          /* NULL */
    init_gdt_desc(0x0, 0xFFFFF, 0x9B, 0x0D, &kgdt[1]);    /* código */
    init_gdt_desc(0x0, 0xFFFFF, 0x93, 0x0D, &kgdt[2]);    /* datos */
    init_gdt_desc(0x0, 0x0, 0x97, 0x0D, &kgdt[3]);        /* pila */

    /* inicialización de la estructura para GDTR */
    kgdtr.limite = GDTSIZE * 8;
    kgdtr.base = GDTBASE;

    /* copia de la GDT a su dirección */
    memcpy((char *) kgdtr.base, (char *) kgdt, kgdtr.limite);

    /* carga del registro GDTR */
    asm("lgdtl (kgdtr)");

    /* inicialización de los segmentos */
    asm("   movw $0x10, %ax \n \
        movw %ax, %ds       \n \
        movw %ax, %es       \n \
        movw %ax, %fs       \n \
        movw %ax, %gs       \n \
        ljmp $0x08, $next   \n \
        next:               \n");
}
