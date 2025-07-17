#include "types.h"
#include "screen.h"
#include "io.h"

/* Variables globales para la pantalla */
u8 kX = 0;
u8 kY = 0;
u8 kattr = 0x07;  /* atributo por defecto: texto gris sobre fondo negro */

/* Puntero al buffer de video */
u16 *videomem = (u16 *)0xB8000;

/*
 * Función para escribir un carácter en la pantalla
 */
void putcar(uchar c)
{
    if (c == '\n') {
        kX = 0;
        kY++;
    } else if (c == '\t') {
        kX = (kX + 8) & ~7;
    } else if (c == '\b') {
        if (kX > 0) {
            kX--;
            videomem[kY * 80 + kX] = (kattr << 8) | ' ';
        }
    } else {
        videomem[kY * 80 + kX] = (kattr << 8) | c;
        kX++;
    }
    
    /* Manejar wrap-around y scroll */
    if (kX >= 80) {
        kX = 0;
        kY++;
    }
    
    if (kY >= 25) {
        kY = 24;
        scrollup();
    }
}

/*
 * Función para imprimir una cadena
 */
void print(char *s)
{
    while (*s) {
        putcar(*s++);
    }
}

/*
 * Función para limpiar la pantalla
 */
void clear_screen(void)
{
    int i;
    for (i = 0; i < 80 * 25; i++) {
        videomem[i] = (kattr << 8) | ' ';
    }
    kX = 0;
    kY = 0;
}

/*
 * Función para hacer scroll hacia arriba
 */
void scrollup(void)
{
    int i;
    
    /* Mover todas las líneas una posición hacia arriba */
    for (i = 0; i < 24 * 80; i++) {
        videomem[i] = videomem[i + 80];
    }
    
    /* Limpiar la última línea */
    for (i = 24 * 80; i < 25 * 80; i++) {
        videomem[i] = (kattr << 8) | ' ';
    }
}

/*
 * Función para imprimir un número en hexadecimal
 */
void print_hex(u32 n)
{
    int i;
    char hex_chars[] = "0123456789ABCDEF";
    
    print("0x");
    for (i = 28; i >= 0; i -= 4) {
        putcar(hex_chars[(n >> i) & 0xF]);
    }
}

/*
 * Función para imprimir un número en decimal
 */
void print_dec(u32 n)
{
    if (n == 0) {
        putcar('0');
        return;
    }
    
    char buf[16];
    int i = 0;
    
    while (n > 0) {
        buf[i++] = '0' + (n % 10);
        n /= 10;
    }
    
    while (i > 0) {
        putcar(buf[--i]);
    }
}

/*
 * Función para volcar datos en hexadecimal
 */
void dump(void *ptr, int size)
{
    uchar *p = (uchar *)ptr;
    int i;
    
    for (i = 0; i < size; i++) {
        if (i > 0 && i % 16 == 0) {
            print("\n");
        }
        if (p[i] < 0x10) {
            putcar('0');
        }
        print_hex(p[i]);
        putcar(' ');
    }
    print("\n");
}
