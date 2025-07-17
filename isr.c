#include "types.h"
#include "screen.h"
#include "io.h"
#include "kbd.h"
#include "process.h"

void isr_default_int(void)
{
    print("interrupt\n");
}

void isr_clock_int(void)
{
    static int tic = 0;
    static int sec = 0;
    static int count = 0;
    
    tic++;
    if (tic % 100 == 0) {
        sec++;
        tic = 0;
        count++;
        
        /* Mostrar un punto cada 30 segundos para indicar que 
           el sistema está funcionando */
        if (count % 30 == 0) {
            /* Solo mostrar dots si no estamos en el shell */
            // putcar('.');
            // show_cursor();
        }
    }
    
    /* Llamar al scheduler solo si hay tareas cargadas */
    if (n_proc > 0) {
        schedule();
    }
}

void isr_kbd_int(void)
{
    uchar i;
    static int lshift_enable = 0;
    static int rshift_enable = 0;
    static int alt_enable = 0;
    static int ctrl_enable = 0;
    
    /* Esperar a que el buffer de salida esté lleno */
    do {
        i = inb(0x64);
    } while ((i & 0x01) == 0);
    
    /* Leer el scan code */
    i = inb(0x60);
    
    /* Procesar el scan code */
    if (i < 0x80) {         /* Tecla presionada (make code) */
        switch (i) {
        case LSHIFT_MAKE:
            lshift_enable = 1;
            break;
        case RSHIFT_MAKE:
            rshift_enable = 1;
            break;
        case CTRL_MAKE:
            ctrl_enable = 1;
            break;
        case ALT_MAKE:
            alt_enable = 1;
            break;
        default:
            /* Verificar si el scan code está en el rango válido */
            if (i < KBDMAP_SIZE) {
                char c = kbdmap[i * 4 + (lshift_enable || rshift_enable)];
                if (c) {
                    /* Agregar al buffer del teclado */
                    kbd_buffer_add(c);
                }
            }
        }
    } else {                /* Tecla liberada (break code) */
        i -= 0x80;
        switch (i) {
        case LSHIFT_MAKE:
            lshift_enable = 0;
            break;
        case RSHIFT_MAKE:
            rshift_enable = 0;
            break;
        case CTRL_MAKE:
            ctrl_enable = 0;
            break;
        case ALT_MAKE:
            alt_enable = 0;
            break;
        }
    }
    
    /* Actualizar la posición del cursor */
    show_cursor();
}
