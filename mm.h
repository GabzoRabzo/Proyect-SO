#ifndef MM_H_
#define MM_H_

#include "types.h"

/* Definiciones para la paginación */
#define PAGING_FLAG     0x80000000      /* CR0 - bit 31 */

/* Tamaño de página y máscaras */
#define PAGE_SIZE       0x1000          /* 4096 bytes = 4KB */
#define PAGE_MASK       0xFFFFF000      /* máscara para obtener la dirección base de página */

/* Flags para las entradas de página */
#define PAGE_PRESENT    0x01            /* Página presente en memoria */
#define PAGE_RW         0x02            /* Página de lectura/escritura */
#define PAGE_USER       0x04            /* Página accesible desde modo usuario */
#define PAGE_ACCESSED   0x20            /* Página accedida */
#define PAGE_DIRTY      0x40            /* Página modificada */

/* Gestión de memoria física */
#define RAM_MAXPAGE     0x10000         /* Número máximo de páginas físicas (1GB / 4KB) */
#define USER_OFFSET     0x40000000      /* Offset base para espacio de usuario */
#define USER_STACK      0xE0000000      /* Dirección de pila de usuario */

/* Macros para manipular direcciones */
#define PAGE(addr)              ((addr) >> 12)           /* Obtener número de página */
#define VADDR_PD_OFFSET(addr)   (((addr) >> 22) & 0x3FF) /* Índice en directorio de páginas */
#define VADDR_PT_OFFSET(addr)   (((addr) >> 12) & 0x3FF) /* Índice en tabla de páginas */
#define HEAP_START       0x200000      // Start of kernel heap (after kernel space)
#define HEAP_MAX_SIZE    0x100000      // 1MB heap initially
#define HEAP_MAGIC       0xDEADBEEF
#define HEAP_MIN_SIZE    16            // Minimum allocation size

/* Heap block structure */
struct heap_block {
    u32 magic;
    u32 size;
    struct heap_block *next;
    u8 used;
} __attribute__((packed));

/* Page heap management */
#define PAGE_HEAP_START  0x300000
#define PAGE_HEAP_MAX    256           // 256 pages (1MB)
#define PAGE_HEAP_ENTRIES 64           // 64 zones (each can manage multiple pages)

struct page_zone {
    u32 start;
    u32 size;
    u8 used;
} __attribute__((packed));
/* Variables globales */
extern u8 mem_bitmap[RAM_MAXPAGE / 8];  /* Bitmap de páginas físicas */
extern u32 *pd0;                        /* kernel page directory */
extern u32 *pt0;                        /* kernel page table */

/* Estructuras para entradas de página */
struct pd_entry {
    u32 present:1;
    u32 writable:1;
    u32 user:1;
    u32 pwt:1;
    u32 pcd:1;
    u32 accessed:1;
    u32 _unused:1;
    u32 page_size:1;
    u32 global:1;
    u32 avail:3;
    u32 page_table_base:20;
} __attribute__ ((packed));

struct pt_entry {
    u32 present:1;
    u32 writable:1;
    u32 user:1;
    u32 pwt:1;
    u32 pcd:1;
    u32 accessed:1;
    u32 dirty:1;
    u32 pat:1;
    u32 global:1;
    u32 avail:3;
    u32 page_base:20;
} __attribute__ ((packed));

/* Funciones para gestión de memoria */
void init_mm(void);
void page_fault_handler(void);
char *get_page_frame(void);
void release_page_frame(u32 p_addr);
u32 *pd_create_task1(void);
void *kmalloc(u32 size);
void kfree(void *ptr);
void *get_page_from_heap(void);
void release_page_from_heap(void *ptr);
void init_heap(void);
void init_page_heap(void);

/* Macros para manipular el bitmap */
#define set_page_frame_used(page)       mem_bitmap[((u32)page)/8] |= (1 << (((u32)page)%8))
#define release_page_frame(p_addr)      mem_bitmap[((u32)p_addr/PAGE_SIZE)/8] &= ~(1 << (((u32)p_addr/PAGE_SIZE)%8))


#endif
