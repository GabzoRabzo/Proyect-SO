#include "lib.h"
#include "mm.h"
#include "screen.h"

#define __PLIST__
#include "process.h"

/*
 * Carga una tarea en memoria física y crea su contexto
 */
void load_task(u32 *code_phys_addr, u32 *fn, unsigned int code_size)
{
    u32 page_base, pages, kstack_base;
    u32 *pd;
    int i;

    print("process: loading task ");
    print_dec(n_proc);
    print(" at 0x");
    print_hex((u32)code_phys_addr);
    print("\n");

    /* Copiar el código a la dirección especificada */
    memcpy((char *)code_phys_addr, (char *)fn, code_size);

    /* Actualizar el bitmap de páginas */
    page_base = (u32)PAGE((u32)code_phys_addr);

    if (code_size % PAGE_SIZE)
        pages = code_size / PAGE_SIZE + 1;
    else
        pages = code_size / PAGE_SIZE;

    for (i = 0; i < pages; i++)
        set_page_frame_used(page_base + i);

    /* Crear el directorio y las tablas de páginas */
    pd = pd_create(code_phys_addr, code_size);
    if (pd == (u32 *)-1) {
        print("process: ERROR: Cannot create page directory\n");
        return;
    }

    /* Asignar pila del kernel */
    kstack_base = (u32)get_page_frame();
    if (kstack_base == (u32)-1) {
        print("process: ERROR: Cannot allocate kernel stack\n");
        return;
    }
    p_list[n_proc].mem_info.code_start = (u32)code_phys_addr;
    p_list[n_proc].mem_info.code_end = (u32)code_phys_addr + code_size;
    p_list[n_proc].mem_info.stack_start = 0x40001000;
    p_list[n_proc].mem_info.stack_end = 0x40002000;
    p_list[n_proc].page_dir = pd;
    
    /* Inicializar los registros del proceso */
    p_list[n_proc].pid = n_proc;
    p_list[n_proc].regs.ss = 0x33;          /* Selector de pila usuario */
    p_list[n_proc].regs.esp = 0x40001000;   /* Puntero de pila usuario */
    p_list[n_proc].regs.cs = 0x23;          /* Selector de código usuario */
    p_list[n_proc].regs.eip = 0x40000000;   /* Punto de entrada */
    p_list[n_proc].regs.ds = 0x2B;          /* Selector de datos usuario */
    p_list[n_proc].regs.es = 0x2B;
    p_list[n_proc].regs.fs = 0x2B;
    p_list[n_proc].regs.gs = 0x2B;
    p_list[n_proc].regs.eflags = 0x202;     /* IF habilitado */
    p_list[n_proc].regs.cr3 = (u32)pd;      /* Directorio de páginas */

    /* Configurar pila del kernel */
    p_list[n_proc].kstack.ss0 = 0x18;       /* Segmento de pila del kernel */
    p_list[n_proc].kstack.esp0 = kstack_base + PAGE_SIZE;

    /* Inicializar otros registros */
    p_list[n_proc].regs.eax = 0;
    p_list[n_proc].regs.ebx = 0;
    p_list[n_proc].regs.ecx = 0;
    p_list[n_proc].regs.edx = 0;
    p_list[n_proc].regs.ebp = 0;
    p_list[n_proc].regs.esi = 0;
    p_list[n_proc].regs.edi = 0;

    n_proc++;
    print("process: task loaded successfully\n");
}

/*
 * Crea un directorio de páginas para una tarea
 */
u32 *pd_create(u32 *code_phys_addr, unsigned int code_size)
{
    u32 *pd, *pt;
    u32 i;

    /* Obtener página para el directorio de páginas */
    pd = (u32 *)get_page_frame();
    if (pd == (u32 *)-1) {
        print("process: ERROR: Cannot allocate page directory\n");
        return (u32 *)-1;
    }

    /* Inicializar directorio de páginas */
    for (i = 0; i < 1024; i++)
        pd[i] = 0;

    /* Obtener página para la tabla de páginas de usuario */
    pt = (u32 *)get_page_frame();
    if (pt == (u32 *)-1) {
        print("process: ERROR: Cannot allocate page table\n");
        return (u32 *)-1;
    }

    /* Inicializar tabla de páginas */
    for (i = 0; i < 1024; i++)
        pt[i] = 0;

    /* Espacio kernel - compartido con todas las tareas */
    pd[0] = (u32)pt0 | PAGE_PRESENT | PAGE_RW;

    /* Espacio usuario - mapear 0x40000000 a la dirección física del código */
    pd[USER_OFFSET >> 22] = (u32)pt | PAGE_PRESENT | PAGE_RW | PAGE_USER;
    pt[0] = (u32)code_phys_addr | PAGE_PRESENT | PAGE_RW | PAGE_USER;

    /* Mapear página adicional para la pila (0x40001000) */
    pt[1] = ((u32)code_phys_addr + PAGE_SIZE) | PAGE_PRESENT | PAGE_RW | PAGE_USER;

    return pd;
}
