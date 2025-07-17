#ifndef _KBD_H_
#define _KBD_H_

#include "types.h"

/* Códigos de scan más comunes */
#define KBDMAP_SIZE 128
#define LSHIFT_MAKE     0x2A
#define LSHIFT_BREAK    0xAA
#define RSHIFT_MAKE     0x36
#define RSHIFT_BREAK    0xB6
#define CTRL_MAKE       0x1D
#define CTRL_BREAK      0x9D
#define ALT_MAKE        0x38
#define ALT_BREAK       0xB8

/* Mapa de teclado QWERTY */
extern const char kbdmap[];

/* Funciones del teclado */
void move_cursor(u8 x, u8 y);
void show_cursor(void);
char kbd_getchar(void);
void kbd_buffer_add(char c);

#endif
