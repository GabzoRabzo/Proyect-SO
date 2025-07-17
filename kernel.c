#include "types.h"
#include "gdt.h"
#include "screen.h"
#include "io.h"
#include "idt.h"
#include "kbd.h"
#include "task.h"
#include "mm.h"
#include "process.h"
#include "ide.h"
#include "fs.h"
#include "shell.h"
#include "lib.h"
#include "elf_data.h"

void init_pic(void);
int main(void);  // Declaración de la función main

// Definiciones que podrían faltar
#ifndef NULL
#define NULL ((void*)0)
#endif

// Estructura para información del multiboot
struct mb_partial_info {
    unsigned long flags;
    unsigned long low_mem;
    unsigned long high_mem;
    unsigned long boot_device;
    unsigned long cmdline;
};

// Función llamada por boot.asm
void kmain(struct mb_partial_info *mbi)
{
    /* Limpiar la pantalla */
    clear_screen();
    
    kY = 2;
    kattr = 0x0E;  /* amarillo sobre negro */
    
    /* Mensaje de bienvenida */
    print("Grub example kernel is loaded...\n");
    
    /* Mostrar información de RAM detectada por GRUB */
    if (mbi && (mbi->flags & 0x1)) {
        print("RAM detected : ");
        print_dec(mbi->low_mem);
        print("k (lower), ");
        print_dec(mbi->high_mem);
        print("k (upper)\n");
    }
    
    /* Inicializar IDT */
    init_idt();
    print("kernel : idt loaded\n");
    
    /* Inicializar PIC */
    init_pic();
    print("kernel : pic configured\n");
    
    /* Inicializar GDT y segmentos */
    init_gdt();
    print("kernel : gdt loaded\n");
    
    /* Inicializar el puntero de pila %esp */
    asm("   movw $0x18, %ax \n \
            movw %ax, %ss \n \
            movl $0x20000, %esp");
    
    main();
}

int main(void)
{
    /* Inicializar gestión de memoria (paginación) */
    init_mm();
    print("kernel : mm initialized\n");
    
    /* Inicializar tareas y TSS */
    init_task();
    print("kernel : task initialized\n");
    
    init_mm();
    init_heap();
    init_page_heap();
    
    print("kernel : memory systems initialized\n");    
    
    /* Inicializar controlador IDE */
    ide_init();
    print("kernel : IDE controller initialized\n");
    
    /* Inicializar sistema de archivos */
    fs_init();
    print("kernel : File system initialized\n");
    
    /* Crear algunos archivos de ejemplo y cargar programas ELF */
    int fd;
    char *sample_text;
    
    sample_text = "Hello from Pepin OS!\nThis is a sample file.\n";
    fd = fs_open_file("readme.txt");
    if (fd >= 0) {
        fs_write_file(fd, sample_text, strlen(sample_text));
        fs_close_file(fd);
    }
    
    sample_text = "Welcome to Pepin OS!\nA simple operating system.\n";
    fd = fs_open_file("welcome.txt");
    if (fd >= 0) {
        fs_write_file(fd, sample_text, strlen(sample_text));
        fs_close_file(fd);
    }
    
    /* Cargar programas ELF al sistema de archivos */
    print("kernel : Loading ELF programs to filesystem...\n");
    
    // Crear hello.elf en el filesystem con los datos reales
    if (fs_create_file("hello.elf", hello_elf_data_size) >= 0) {
        fd = fs_open_file("hello.elf");
        if (fd >= 0) {
            // Escribir los datos ELF completos
            fs_write_file(fd, hello_elf_data, hello_elf_data_size);
            fs_close_file(fd);
            print("kernel : hello.elf created in filesystem (");
            print_dec(hello_elf_data_size);
            print(" bytes)\n");
        }
    }
    
    // Crear calc.elf en el filesystem con los datos reales
    if (fs_create_file("calc.elf", calc_elf_data_size) >= 0) {
        fd = fs_open_file("calc.elf");
        if (fd >= 0) {
            // Escribir los datos ELF completos
            fs_write_file(fd, calc_elf_data, calc_elf_data_size);
            fs_close_file(fd);
            print("kernel : calc.elf created in filesystem (");
            print_dec(calc_elf_data_size);
            print(" bytes)\n");
        }
    }
    
    print("kernel : ELF programs loaded successfully\n");
    
    kattr = 0x47;  /* texto blanco sobre fondo rojo */
    print("kernel : allowing interrupt\n");
    kattr = 0x07;  /* restaurar atributos normales */
    
    /* Mostrar mensaje de bienvenida */
    print("\n");
    print("===================================\n");
    print("     Pepin Operating System\n");
    print("===================================\n");
    print("\n");
    print("Sistema multitarea iniciado\n");
    print("Interrupciones habilitadas\n");
    
    /* Habilitar interrupciones */
    sti;
    
    /* Mostrar el cursor */
    show_cursor();
    
    print("Pepin is booting...\n");
    print("RAM detected : 639k (lower), 31660k (upper)\n");
    print("Loading IDT\n");
    print("Configure PIC\n");
    print("Loading Task Register\n");
    print("Enabling paging\n");
    print("Interrupts are enable. System is ready !\n");
    print("\n");
    
    /* Inicializar e iniciar el shell */
    shell_init();
    shell_run();
    
    /* El sistema ahora funciona con multitarea y shell */
    while (1) {
        asm("hlt");
    }
}
