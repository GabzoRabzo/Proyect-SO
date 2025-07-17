#ifndef TASK_H_
#define TASK_H_

#include "types.h"

/* Estructura TSS (Task State Segment) */
struct tss {
    u32 prev_task_link;
    u32 esp0;
    u32 ss0;
    u32 esp1;
    u32 ss1;
    u32 esp2;
    u32 ss2;
    u32 cr3;
    u32 eip;
    u32 eflags;
    u32 eax;
    u32 ecx;
    u32 edx;
    u32 ebx;
    u32 esp;
    u32 ebp;
    u32 esi;
    u32 edi;
    u32 es;
    u32 cs;
    u32 ss;
    u32 ds;
    u32 fs;
    u32 gs;
    u32 ldt;
    u16 io_map;
    u16 debug_flag;
} __attribute__ ((packed));

/* Variable global del TSS */
extern struct tss default_tss;

/* Funciones de tareas */
void task1(void);
void task2(void);
void task3(void);

/* Funciones de inicialización */
void init_task(void);
void start_task(void);

#endif
