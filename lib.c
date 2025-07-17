#include "lib.h"

/*
 * memcpy: copia 'count' bytes de 'src' a 'dest'
 */
void *memcpy(void *dest, const void *src, u32 count)
{
    char *d = (char*)dest;
    const char *s = (const char*)src;
    
    while (count--)
        *d++ = *s++;
    
    return dest;
}

/*
 * memset: llena 'count' bytes de 'dest' con 'val'
 */
void *memset(void *dest, u8 val, u32 count)
{
    char *d = (char*)dest;
    
    while (count--)
        *d++ = val;
    
    return dest;
}

/*
 * strlen: calcula la longitud de una cadena
 */
u32 strlen(const char *s)
{
    u32 len = 0;
    
    while (*s++)
        len++;
    
    return len;
}

/*
 * strcmp: compara dos cadenas
 */
int strcmp(const char *s1, const char *s2)
{
    while (*s1 && *s2) {
        if (*s1 != *s2) {
            return *s1 - *s2;
        }
        s1++;
        s2++;
    }
    return *s1 - *s2;
}

void insl(int port, void *addr, int cnt) {
    asm volatile(
        "cld\n\t"
        "repne\n\t"
        "insl"
        : "=D" (addr), "=c" (cnt)
        : "d" (port), "0" (addr), "1" (cnt)
        : "memory", "cc"
    );
}

// Escribir múltiples palabras de 32 bits a un puerto
void outsl(int port, const void *addr, int cnt) {
    asm volatile(
        "cld\n\t"
        "repne\n\t"
        "outsl"
        : "=S" (addr), "=c" (cnt)
        : "d" (port), "0" (addr), "1" (cnt)
        : "cc"
    );
}
