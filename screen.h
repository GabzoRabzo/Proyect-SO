#ifndef SCREEN_H_
#define SCREEN_H_

#include "types.h"

/* Variables globales para la pantalla */
extern u8 kX;        /* posición X del cursor */
extern u8 kY;        /* posición Y del cursor */
extern u8 kattr;     /* atributo de color actual */

/* Funciones de pantalla */
void putcar(uchar c);
void print(char *s);
void clear_screen(void);
void scrollup(void);
void print_hex(u32 n);
void print_dec(u32 n);
void dump(void *ptr, int size);

#endif
