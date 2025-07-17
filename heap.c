#include "mm.h"
#include "screen.h"
#include "lib.h"

static struct heap_block *heap_start = (struct heap_block *)HEAP_START;
static struct page_zone page_zones[PAGE_HEAP_ENTRIES];

void init_heap(void) {
    heap_start->magic = HEAP_MAGIC;
    heap_start->size = HEAP_MAX_SIZE - sizeof(struct heap_block);
    heap_start->next = 0;
    heap_start->used = 0;
    print("heap   : kernel heap initialized at 0x");
    print_hex(HEAP_START);
    print("\n");
}

void *kmalloc(u32 size) {
    struct heap_block *curr, *prev = 0;
    u32 total_size;
    
    // Align size to 4 bytes
    size = (size + 3) & ~3;
    if (size < HEAP_MIN_SIZE) size = HEAP_MIN_SIZE;
    
    total_size = size + sizeof(struct heap_block);
    
    curr = heap_start;
    while (curr) {
        if (!curr->used && curr->size >= size) {
            // Split block if there's enough space left
            if (curr->size > total_size + sizeof(struct heap_block) + HEAP_MIN_SIZE) {
                struct heap_block *new_block = (struct heap_block *)((u32)curr + total_size);
                new_block->magic = HEAP_MAGIC;
                new_block->size = curr->size - total_size;
                new_block->next = curr->next;
                new_block->used = 0;
                
                curr->size = size;
                curr->next = new_block;
            }
            
            curr->used = 1;
            return (void *)((u32)curr + sizeof(struct heap_block));
        }
        prev = curr;
        curr = curr->next;
    }
    
    // No suitable block found
    print("heap   : ERROR - Out of memory!\n");
    return 0;
}

void kfree(void *ptr) {
    struct heap_block *block = (struct heap_block *)((u32)ptr - sizeof(struct heap_block));
    
    if (block->magic != HEAP_MAGIC) {
        print("heap   : ERROR - Invalid free!\n");
        return;
    }
    
    block->used = 0;
    
    // Merge with next block if free
    if (block->next && !block->next->used) {
        block->size += block->next->size + sizeof(struct heap_block);
        block->next = block->next->next;
    }
}

void init_page_heap(void) {
    memset(page_zones, 0, sizeof(page_zones));
    print("heap   : page heap initialized\n");
}

void *get_page_from_heap(void) {
    for (int i = 0; i < PAGE_HEAP_ENTRIES; i++) {
        if (!page_zones[i].used) {
            page_zones[i].start = (u32)get_page_frame();
            if (page_zones[i].start == (u32)-1) {
                print("heap   : ERROR - No physical pages available!\n");
                return 0;
            }
            
            page_zones[i].size = PAGE_SIZE;
            page_zones[i].used = 1;
            
            // Map the page in kernel space
            u32 vaddr = PAGE_HEAP_START + (i * PAGE_SIZE);
            u32 *pt = (u32 *)0xFFC00000; // Recursive mapping
            
            pt[(vaddr >> 12) & 0x3FF] = page_zones[i].start | PAGE_PRESENT | PAGE_RW;
            asm("invlpg %0"::"m"(vaddr));
            
            return (void *)vaddr;
        }
    }
    
    print("heap   : ERROR - Page heap full!\n");
    return 0;
}

void release_page_from_heap(void *ptr) {
    u32 vaddr = (u32)ptr;
    if (vaddr < PAGE_HEAP_START || vaddr >= PAGE_HEAP_START + (PAGE_HEAP_ENTRIES * PAGE_SIZE)) {
        print("heap   : ERROR - Invalid page free!\n");
        return;
    }
    
    int idx = (vaddr - PAGE_HEAP_START) / PAGE_SIZE;
    if (!page_zones[idx].used) {
        print("heap   : ERROR - Page already free!\n");
        return;
    }
    
    // Unmap the page
    u32 *pt = (u32 *)0xFFC00000;
    pt[(vaddr >> 12) & 0x3FF] = 0;
    asm("invlpg %0"::"m"(vaddr));
    
    // Release physical page
    release_page_frame(page_zones[idx].start);
    page_zones[idx].used = 0;
}
