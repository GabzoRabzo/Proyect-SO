#include "types.h"
#include "io.h"

/*
 * Inicialización del controlador de interrupciones PIC 8259A
 */
void init_pic(void)
{
    /* Inicialización del PIC maestro */
    outb(0x20, 0x11);      /* ICW1 */
    outb(0x21, 0x20);      /* ICW2 */
    outb(0x21, 0x04);      /* ICW3 */
    outb(0x21, 0x01);      /* ICW4 */
    
    /* Inicialización del PIC esclavo */
    outb(0xA0, 0x11);      /* ICW1 */
    outb(0xA1, 0x70);      /* ICW2 */
    outb(0xA1, 0x02);      /* ICW3 */
    outb(0xA1, 0x01);      /* ICW4 */
    
    /* Habilitar todas las interrupciones */
    outb(0x21, 0x0);       /* maestro */
    outb(0xA1, 0x0);       /* esclavo */
}
