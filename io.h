#ifndef _IO_H_
#define _IO_H_

/* desactiva las interrupciones */
#define cli asm("cli"::)

/* reactiva las interrupciones */
#define sti asm("sti"::)

/* escribe un byte en un puerto */
#define outb(port,value) \
        asm volatile ("outb %%al, %%dx" :: "d" (port), "a" (value));

/* escribe un byte en un puerto y marca una temporización */
#define outbp(port,value) \
        asm volatile ("outb %%al, %%dx; jmp 1f; 1:" :: "d" (port), "a" (value));

/* lee un byte de un puerto */
#define inb(port) ({    \
        unsigned char _v;       \
        asm volatile ("inb %%dx, %%al" : "=a" (_v) : "d" (port)); \
        _v;     \
})

#endif
