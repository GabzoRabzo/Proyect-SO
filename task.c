#include "task.h"
#include "gdt.h"
#include "lib.h"
#include "screen.h"
#include "mm.h"

/* TSS por defecto */
struct tss default_tss;

/*
 * Tarea de usuario 1
 */
void task1(void)
{
    char *msg = (char*)0x40000100;
    int i = 0;
    
    msg[0] = 'T';
    msg[1] = 'A';
    msg[2] = 'S';
    msg[3] = 'K';
    msg[4] = '1';
    msg[5] = ':';
    msg[6] = ' ';
    msg[7] = '0';
    msg[8] = '\n';
    msg[9] = 0;
    
    while(1) {
        /* Mostrar mensaje */
        asm("mov %0, %%ebx; mov $0x01, %%eax; int $0x30" :: "m" (msg));
        
        /* Incrementar contador */
        i++;
        msg[7] = '0' + (i % 10);
        
        /* Pequeño delay */
        for (int j = 0; j < 100000; j++);
    }
}

/*
 * Tarea de usuario 2
 */
void task2(void)
{
    char *msg = (char*)0x40000100;
    int i = 0;
    
    msg[0] = 'T';
    msg[1] = 'A';
    msg[2] = 'S';
    msg[3] = 'K';
    msg[4] = '2';
    msg[5] = ':';
    msg[6] = ' ';
    msg[7] = 'A';
    msg[8] = '\n';
    msg[9] = 0;
    
    while(1) {
        /* Mostrar mensaje */
        asm("mov %0, %%ebx; mov $0x01, %%eax; int $0x30" :: "m" (msg));
        
        /* Incrementar contador */
        i++;
        msg[7] = 'A' + (i % 26);
        
        /* Pequeño delay */
        for (int j = 0; j < 150000; j++);
    }
}

/*
 * Tarea de usuario 3
 */
void task3(void)
{
    char *msg = (char*)0x40000100;
    int i = 0;
    
    msg[0] = 'T';
    msg[1] = 'A';
    msg[2] = 'S';
    msg[3] = 'K';
    msg[4] = '3';
    msg[5] = ':';
    msg[6] = ' ';
    msg[7] = '*';
    msg[8] = '\n';
    msg[9] = 0;
    
    while(1) {
        /* Mostrar mensaje */
        asm("mov %0, %%ebx; mov $0x01, %%eax; int $0x30" :: "m" (msg));
        
        /* Incrementar contador */
        i++;
        if (i % 2 == 0) {
            msg[7] = '*';
        } else {
            msg[7] = '#';
        }
        
        /* Pequeño delay */
        for (int j = 0; j < 200000; j++);
    }
}

/*
 * Inicializa el TSS y los segmentos de usuario
 */
void init_task(void)
{
    /* Inicializar la estructura TSS */
    default_tss.debug_flag = 0x00;
    default_tss.io_map = 0x00;
    default_tss.esp0 = 0x20000;    /* Pila del kernel */
    default_tss.ss0 = 0x18;        /* Segmento de pila del kernel */
    
    /* Segmentos de usuario */
    init_gdt_desc(0x0, 0xFFFFF, 0xFB, 0x0D, &kgdt[4]); /* Código usuario */
    init_gdt_desc(0x0, 0xFFFFF, 0xF3, 0x0D, &kgdt[5]); /* Datos usuario */
    init_gdt_desc(0x0, 0x0, 0xF7, 0x0D, &kgdt[6]);     /* Pila usuario */
    
    /* Descriptor de TSS */
    init_gdt_desc((u32)&default_tss, sizeof(struct tss), 0xE9, 0x00, &kgdt[7]);
    
    /* Recargar la GDT */
    kgdtr.limite = GDTSIZE * 8;
    kgdtr.base = GDTBASE;
    memcpy((char *)kgdtr.base, (char *)kgdt, kgdtr.limite);
    asm("lgdtl (kgdtr)");
    
    /* Cargar el registro TR con el selector de TSS */
    asm("movw $0x38, %%ax \n ltr %%ax" : : );
    
    print("task   : TSS initialized\n");
    print("task   : user segments created\n");
    print("task   : multitasking system ready\n");
}

/*
 * Esta función ya no se usa en el sistema multitarea
 * Las tareas se cargan usando load_task() en process.c
 */
void start_task(void)
{
    print("task   : start_task() deprecated - using multitasking\n");
}
