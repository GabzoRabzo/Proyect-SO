#include "mm.h"
#include "screen.h"
#include "lib.h"

/* Variables globales */
u8 mem_bitmap[RAM_MAXPAGE / 8];  /* Bitmap de páginas físicas */
u32 *pd0;                        /* kernel page directory */
u32 *pt0;                        /* kernel page table */

/*
 * Obtiene una página física libre y la marca como usada
 */
char *get_page_frame(void)
{
    int byte, bit;
    int page = -1;

    for (byte = 0; byte < RAM_MAXPAGE / 8; byte++) {
        if (mem_bitmap[byte] != 0xFF) {
            for (bit = 0; bit < 8; bit++) {
                if (!(mem_bitmap[byte] & (1 << bit))) {
                    page = 8 * byte + bit;
                    set_page_frame_used(page);
                    return (char *)(page * PAGE_SIZE);
                }
            }
        }
    }
    return (char *)-1;  /* No hay páginas libres */
}

/*
 * Inicializa la gestión de memoria con paginación
 */
void init_mm(void)
{
    u32 page_addr;
    int i, pg;

    print("mm     : initializing memory management...\n");

    /* Inicializar el bitmap de páginas físicas */
    for (pg = 0; pg < RAM_MAXPAGE / 8; pg++)
        mem_bitmap[pg] = 0;

    /* Marcar páginas reservadas para el kernel (0x0 - 0x20000) */
    for (pg = PAGE(0x0); pg < PAGE(0x20000); pg++)
        set_page_frame_used(pg);

    /* Marcar páginas reservadas para hardware (0xA0000 - 0x100000) */
    for (pg = PAGE(0xA0000); pg < PAGE(0x100000); pg++)
        set_page_frame_used(pg);

    /* Obtener páginas dinámicamente para el directorio y tabla de páginas del kernel */
    pd0 = (u32 *)get_page_frame();
    if (pd0 == (u32 *)-1) {
        print("mm     : ERROR: Cannot allocate page directory\n");
        while(1) asm("hlt");
    }
    
    pt0 = (u32 *)get_page_frame();
    if (pt0 == (u32 *)-1) {
        print("mm     : ERROR: Cannot allocate page table\n");
        while(1) asm("hlt");
    }

    /* Inicializar el Page Directory del kernel */
    pd0[0] = (u32)pt0 | PAGE_PRESENT | PAGE_RW;  /* Sin PAGE_USER para el kernel */
    for (i = 1; i < 1024; i++)
        pd0[i] = 0;

    /* Inicializar la primera Page Table con identity mapping para los primeros 4MB */
    page_addr = 0;
    for (i = 0; i < 1024; i++) {
        pt0[i] = page_addr | PAGE_PRESENT | PAGE_RW;  /* Sin PAGE_USER para el kernel */
        page_addr += PAGE_SIZE;
    }

    print("mm     : page directory created at 0x");
    print_hex((u32)pd0);
    print("\n");
    print("mm     : page table[0] created at 0x");
    print_hex((u32)pt0);
    print("\n");
    print("mm     : identity mapping for first 4MB established\n");

    /* Cargar el Page Directory en CR3 y activar la paginación */
    asm("   mov %0, %%eax    \n"
        "   mov %%eax, %%cr3 \n"
        "   mov %%cr0, %%eax \n"
        "   or %1, %%eax     \n"
        "   mov %%eax, %%cr0 \n"
        :: "r"(pd0), "i"(PAGING_FLAG) : "eax");

    print("mm     : paging enabled successfully\n");
}

/*
 * Crea un directorio de páginas para una tarea de usuario
 */
u32 *pd_create_task1(void)
{
    u32 *pd, *pt;
    u32 i;

    print("mm     : creating user task page directory...\n");

    /* Obtener y inicializar una página para el Page Directory */
    pd = (u32 *)get_page_frame();
    if (pd == (u32 *)-1) {
        print("mm     : ERROR: Cannot allocate user page directory\n");
        return (u32 *)-1;
    }
    
    for (i = 0; i < 1024; i++)
        pd[i] = 0;

    /* Obtener y inicializar una página para la Page Table de usuario */
    pt = (u32 *)get_page_frame();
    if (pt == (u32 *)-1) {
        print("mm     : ERROR: Cannot allocate user page table\n");
        return (u32 *)-1;
    }
    
    for (i = 0; i < 1024; i++)
        pt[i] = 0;

    /* Espacio kernel - compartido con todas las tareas (identity mapping) */
    pd[0] = (u32)pt0 | PAGE_PRESENT | PAGE_RW;  /* Sin PAGE_USER para protección */

    /* Espacio usuario - mapear 0x40000000 a 0x100000 */
    pd[USER_OFFSET >> 22] = (u32)pt | PAGE_PRESENT | PAGE_RW | PAGE_USER;
    pt[0] = 0x100000 | PAGE_PRESENT | PAGE_RW | PAGE_USER;

    print("mm     : user page directory created at 0x");
    print_hex((u32)pd);
    print("\n");
    print("mm     : user page table created at 0x");
    print_hex((u32)pt);
    print("\n");

    return pd;
}

/*
 * Manejador de Page Fault
 */
void page_fault_handler(void)
{
    u32 fault_addr;
    u32 error_code;
    
    /* Obtener la dirección que causó el page fault desde CR2 */
    asm("mov %%cr2, %0" : "=r" (fault_addr));
    
    /* El código de error está en la pila, necesitamos accederlo correctamente */
    asm("mov 40(%%esp), %0" : "=r" (error_code));  /* Ajuste para el stack frame */
    
    print("mm     : PAGE FAULT EXCEPTION!\n");
    print("mm     : fault address: 0x");
    print_hex(fault_addr);
    print("\n");
    print("mm     : error code: 0x");
    print_hex(error_code);
    print("\n");
    
    /* Analizar el código de error */
    if (error_code & 0x01) {
        print("mm     : page protection violation\n");
    } else {
        print("mm     : page not present\n");
    }
    
    if (error_code & 0x02) {
        print("mm     : write operation\n");
    } else {
        print("mm     : read operation\n");
    }
    
    if (error_code & 0x04) {
        print("mm     : user mode access\n");
    } else {
        print("mm     : supervisor mode access\n");
    }
    
    print("mm     : system halted\n");
    
    /* Detener el sistema */
    while(1) {
        asm("hlt");
    }
}


void init_recursive_paging(void) {
    // Map the last PDE to point to itself
    pd0[1023] = (u32)pd0 | PAGE_PRESENT | PAGE_RW;
    
    print("mm     : recursive paging enabled\n");
}

void *get_pt_entry(u32 vaddr) {
    u32 *pd = (u32 *)0xFFFFF000; // Recursive mapping of page directory
    u32 pde_idx = (vaddr >> 22) & 0x3FF;
    
    if (!(pd[pde_idx] & PAGE_PRESENT)) {
        // Create new page table if needed
        u32 *pt = (u32 *)get_page_from_heap();
        if (!pt) return 0;
        
        memset(pt, 0, PAGE_SIZE);
        pd[pde_idx] = (u32)pt | PAGE_PRESENT | PAGE_RW | PAGE_USER;
    }
    
    u32 *pt = (u32 *)(0xFFC00000 + (pde_idx << 12)); // Recursive mapping of page tables
    return &pt[(vaddr >> 12) & 0x3FF];
}

void map_page(u32 vaddr, u32 paddr, u32 flags) {
    u32 *entry = (u32 *)get_pt_entry(vaddr);
    if (!entry) {
        print("mm     : ERROR - Failed to get page table entry\n");
        return;
    }
    
    *entry = paddr | flags;
    asm("invlpg %0"::"m"(vaddr));
}

void unmap_page(u32 vaddr) {
    u32 *entry = (u32 *)get_pt_entry(vaddr);
    if (entry && (*entry & PAGE_PRESENT)) {
        *entry = 0;
        asm("invlpg %0"::"m"(vaddr));
    }
}
