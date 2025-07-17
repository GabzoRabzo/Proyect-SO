#include "elf.h"
#include "lib.h"
#include "screen.h"
#include "mm.h"
#include "fs.h"

/* Validar header ELF */
int elf_validate(const struct elf_header *header) {
    // Verificar magic number
    if (header->e_ident[EI_MAG0] != ELFMAG0 ||
        header->e_ident[EI_MAG1] != ELFMAG1 ||
        header->e_ident[EI_MAG2] != ELFMAG2 ||
        header->e_ident[EI_MAG3] != ELFMAG3) {
        return 0;
    }
    
    // Verificar clase (32-bit)
    if (header->e_ident[EI_CLASS] != ELFCLASS32) {
        return 0;
    }
    
    // Verificar endianness (little-endian)
    if (header->e_ident[EI_DATA] != ELFDATA2LSB) {
        return 0;
    }
    
    // Verificar versión
    if (header->e_ident[EI_VERSION] != EV_CURRENT) {
        return 0;
    }
    
    // Verificar tipo (ejecutable)
    if (header->e_type != ET_EXEC) {
        return 0;
    }
    
    // Verificar arquitectura (i386)
    if (header->e_machine != EM_386) {
        return 0;
    }
    
    return 1;
}

/* Cargar archivo ELF en memoria */
u32 elf_load(const void *elf_data, u32 size) {
    const struct elf_header *header = (const struct elf_header *)elf_data;
    
    // Validar el header
    if (!elf_validate(header)) {
        print("ELF    : Invalid ELF header\n");
        return 0;
    }
    
    print("ELF    : Valid ELF file, entry point: 0x");
    print_hex(header->e_entry);
    print("\n");
    
    // Obtener program headers
    const struct elf_program_header *ph = 
        (const struct elf_program_header *)((u8 *)elf_data + header->e_phoff);
    
    // Procesar cada program header
    for (int i = 0; i < header->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD) {
            print("ELF    : Loading segment ");
            print_dec(i);
            print(" at 0x");
            print_hex(ph[i].p_vaddr);
            print(" (");
            print_dec(ph[i].p_filesz);
            print(" bytes)\n");
            
            // Asignar memoria para el segmento
            void *dest = (void *)ph[i].p_vaddr;
            
            // Copiar datos del archivo
            if (ph[i].p_filesz > 0) {
                memcpy(dest, (u8 *)elf_data + ph[i].p_offset, ph[i].p_filesz);
            }
            
            // Limpiar el resto con ceros si es necesario
            if (ph[i].p_memsz > ph[i].p_filesz) {
                memset((u8 *)dest + ph[i].p_filesz, 0, 
                       ph[i].p_memsz - ph[i].p_filesz);
            }
        }
    }
    
    return header->e_entry;
}

/* Ejecutar un archivo ELF */
int elf_execute(const char *filename) {
    // Abrir el archivo
    int fd = fs_open_file(filename);
    if (fd < 0) {
        print("ELF    : Cannot open file ");
        print(filename);
        print("\n");
        return -1;
    }
    
    // Obtener información del archivo
    struct file_entry *file = fs_find_file(filename);
    if (file == NULL) {
        fs_close_file(fd);
        return -1;
    }
    
    // Asignar memoria para el archivo
    void *elf_data = kmalloc(file->size);
    if (elf_data == NULL) {
        print("ELF    : Cannot allocate memory for ");
        print(filename);
        print("\n");
        fs_close_file(fd);
        return -1;
    }
    
    // Leer el archivo completo
    if (fs_read_file(fd, elf_data, file->size) != (int)file->size) {
        print("ELF    : Cannot read file ");
        print(filename);
        print("\n");
        kfree(elf_data);
        fs_close_file(fd);
        return -1;
    }
    
    fs_close_file(fd);
    
    // Cargar el ELF
    u32 entry_point = elf_load(elf_data, file->size);
    if (entry_point == 0) {
        print("ELF    : Cannot load ");
        print(filename);
        print("\n");
        kfree(elf_data);
        return -1;
    }
    
    print("ELF    : Executing ");
    print(filename);
    print(" at 0x");
    print_hex(entry_point);
    print("\n");
    
    // Ejecutar el programa (saltar a la entrada)
    // Nota: esto es una versión simplificada, en un OS real
    // necesitaríamos configurar un nuevo espacio de proceso
    void (*program_entry)(void) = (void (*)(void))entry_point;
    program_entry();
    
    kfree(elf_data);
    return 0;
}