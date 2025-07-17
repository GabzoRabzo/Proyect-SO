#ifndef PROCESS_H_
#define PROCESS_H_

#include "types.h"

/* Estructura para almacenar el contexto de un proceso */
struct process {
    unsigned int pid;

    struct {
        u32 eax, ecx, edx, ebx;
        u32 esp, ebp, esi, edi;
        u32 eip, eflags;
        u32 cs:16, ss:16, ds:16, es:16, fs:16, gs:16;
        u32 cr3;
    } regs __attribute__ ((packed));

    struct {
        u32 esp0;
        u16 ss0;
    } kstack __attribute__ ((packed));
    
    struct {
        u32 code_start;
        u32 code_end;
        u32 stack_start;
        u32 stack_end;
        u32 heap_start;
        u32 heap_end;
    } mem_info;
    
    u32 *page_dir;
    u32 *page_tables[1024];
    
} __attribute__ ((packed));

/* Modos de ejecución */
#define USERMODE   0
#define KERNELMODE 1

/* Número máximo de procesos */
#define MAX_PROCESSES 32

/* Variables globales */
#ifdef __PLIST__
struct process p_list[MAX_PROCESSES];   /* Lista de procesos */
struct process *current = 0;            /* Proceso actual */
int n_proc = 0;                         /* Número de procesos */
#else
extern struct process p_list[MAX_PROCESSES];
extern struct process *current;
extern int n_proc;
#endif

/* Funciones */
void load_task(u32 *code_phys_addr, u32 *fn, unsigned int code_size);
void schedule(void);
void switch_to_task(int n, int mode);
u32 *pd_create(u32 *code_phys_addr, unsigned int code_size);

#endif
