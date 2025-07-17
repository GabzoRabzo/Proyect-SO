#include "types.h"
#include "kbd.h"
#include "io.h"
#include "screen.h"

/*
 * Mapa de teclado QWERTY
 * Cada tecla tiene 4 valores: normal, shift, ctrl, alt
 */
const char kbdmap[] = {
    0, 0, 0, 0,             /* 0x00 - none */
    0, 0, 0, 0,             /* 0x01 - ESC */
    '1', '!', 0, 0,         /* 0x02 - 1 */
    '2', '@', 0, 0,         /* 0x03 - 2 */
    '3', '#', 0, 0,         /* 0x04 - 3 */
    '4', '$', 0, 0,         /* 0x05 - 4 */
    '5', '%', 0, 0,         /* 0x06 - 5 */
    '6', '^', 0, 0,         /* 0x07 - 6 */
    '7', '&', 0, 0,         /* 0x08 - 7 */
    '8', '*', 0, 0,         /* 0x09 - 8 */
    '9', '(', 0, 0,         /* 0x0A - 9 */
    '0', ')', 0, 0,         /* 0x0B - 0 */
    '-', '_', 0, 0,         /* 0x0C - - */
    '=', '+', 0, 0,         /* 0x0D - = */
    '\b', '\b', 0, 0,       /* 0x0E - backspace */
    '\t', '\t', 0, 0,       /* 0x0F - tab */
    'q', 'Q', 0, 0,         /* 0x10 - q */
    'w', 'W', 0, 0,         /* 0x11 - w */
    'e', 'E', 0, 0,         /* 0x12 - e */
    'r', 'R', 0, 0,         /* 0x13 - r */
    't', 'T', 0, 0,         /* 0x14 - t */
    'y', 'Y', 0, 0,         /* 0x15 - y */
    'u', 'U', 0, 0,         /* 0x16 - u */
    'i', 'I', 0, 0,         /* 0x17 - i */
    'o', 'O', 0, 0,         /* 0x18 - o */
    'p', 'P', 0, 0,         /* 0x19 - p */
    '[', '{', 0, 0,         /* 0x1A - [ */
    ']', '}', 0, 0,         /* 0x1B - ] */
    '\n', '\n', 0, 0,       /* 0x1C - enter */
    0, 0, 0, 0,             /* 0x1D - ctrl */
    'a', 'A', 0, 0,         /* 0x1E - a */
    's', 'S', 0, 0,         /* 0x1F - s */
    'd', 'D', 0, 0,         /* 0x20 - d */
    'f', 'F', 0, 0,         /* 0x21 - f */
    'g', 'G', 0, 0,         /* 0x22 - g */
    'h', 'H', 0, 0,         /* 0x23 - h */
    'j', 'J', 0, 0,         /* 0x24 - j */
    'k', 'K', 0, 0,         /* 0x25 - k */
    'l', 'L', 0, 0,         /* 0x26 - l */
    ';', ':', 0, 0,         /* 0x27 - ; */
    '\'', '"', 0, 0,        /* 0x28 - ' */
    '`', '~', 0, 0,         /* 0x29 - ` */
    0, 0, 0, 0,             /* 0x2A - lshift */
    '\\', '|', 0, 0,        /* 0x2B - \ */
    'z', 'Z', 0, 0,         /* 0x2C - z */
    'x', 'X', 0, 0,         /* 0x2D - x */
    'c', 'C', 0, 0,         /* 0x2E - c */
    'v', 'V', 0, 0,         /* 0x2F - v */
    'b', 'B', 0, 0,         /* 0x30 - b */
    'n', 'N', 0, 0,         /* 0x31 - n */
    'm', 'M', 0, 0,         /* 0x32 - m */
    ',', '<', 0, 0,         /* 0x33 - , */
    '.', '>', 0, 0,         /* 0x34 - . */
    '/', '?', 0, 0,         /* 0x35 - / */
    0, 0, 0, 0,             /* 0x36 - rshift */
    '*', '*', 0, 0,         /* 0x37 - * (numpad) */
    0, 0, 0, 0,             /* 0x38 - alt */
    ' ', ' ', 0, 0,         /* 0x39 - space */
    0, 0, 0, 0,             /* 0x3A - caps */
};

/*
 * Mueve el cursor a la posición especificada
 */
void move_cursor(u8 x, u8 y)
{
    u16 c_pos;

    c_pos = y * 80 + x;
    outb(0x3d4, 0x0f);
    outb(0x3d5, (u8) c_pos);
    outb(0x3d4, 0x0e);
    outb(0x3d5, (u8) (c_pos >> 8));
}

/*
 * Muestra el cursor en la posición actual
 */
void show_cursor(void)
{
    move_cursor(kX, kY);
}

/*
 * Buffer circular para caracteres del teclado
 */
static char kbd_buffer[256];
static int kbd_buffer_head = 0;
static int kbd_buffer_tail = 0;

/*
 * Agregar carácter al buffer
 */
void kbd_buffer_add(char c)
{
    kbd_buffer[kbd_buffer_head] = c;
    kbd_buffer_head = (kbd_buffer_head + 1) % 256;
    
    // Si el buffer está lleno, mover la cola
    if (kbd_buffer_head == kbd_buffer_tail) {
        kbd_buffer_tail = (kbd_buffer_tail + 1) % 256;
    }
}

/*
 * Obtener carácter del buffer
 */
char kbd_getchar(void)
{
    // Esperar hasta que haya un carácter disponible
    while (kbd_buffer_head == kbd_buffer_tail) {
        asm("hlt");  // Esperar por interrupción
    }
    
    char c = kbd_buffer[kbd_buffer_tail];
    kbd_buffer_tail = (kbd_buffer_tail + 1) % 256;
    
    return c;
}
