#ifndef ELF_H
#define ELF_H

#include "types.h"

/* Constantes ELF */
#define EI_NIDENT 16
#define EI_MAG0   0
#define EI_MAG1   1
#define EI_MAG2   2
#define EI_MAG3   3
#define EI_CLASS  4
#define EI_DATA   5
#define EI_VERSION 6

#define ELFMAG0   0x7F
#define ELFMAG1   'E'
#define ELFMAG2   'L'
#define ELFMAG3   'F'

#define ELFCLASS32 1
#define ELFDATA2LSB 1
#define EV_CURRENT 1

/* Tipos de archivos ELF */
#define ET_NONE 0
#define ET_REL  1
#define ET_EXEC 2
#define ET_DYN  3

/* Arquitecturas */
#define EM_386  3

/* Tipos de segmento */
#define PT_NULL    0
#define PT_LOAD    1
#define PT_DYNAMIC 2
#define PT_INTERP  3
#define PT_NOTE    4
#define PT_SHLIB   5
#define PT_PHDR    6

/* Flags de segmento */
#define PF_X 0x1  /* Ejecutable */
#define PF_W 0x2  /* Escribible */
#define PF_R 0x4  /* Legible */

/* Header ELF */
struct elf_header {
    u8  e_ident[EI_NIDENT];
    u16 e_type;
    u16 e_machine;
    u32 e_version;
    u32 e_entry;
    u32 e_phoff;
    u32 e_shoff;
    u32 e_flags;
    u16 e_ehsize;
    u16 e_phentsize;
    u16 e_phnum;
    u16 e_shentsize;
    u16 e_shnum;
    u16 e_shstrndx;
} __attribute__((packed));

/* Program header */
struct elf_program_header {
    u32 p_type;
    u32 p_offset;
    u32 p_vaddr;
    u32 p_paddr;
    u32 p_filesz;
    u32 p_memsz;
    u32 p_flags;
    u32 p_align;
} __attribute__((packed));

/* Section header */
struct elf_section_header {
    u32 sh_name;
    u32 sh_type;
    u32 sh_flags;
    u32 sh_addr;
    u32 sh_offset;
    u32 sh_size;
    u32 sh_link;
    u32 sh_info;
    u32 sh_addralign;
    u32 sh_entsize;
} __attribute__((packed));

/* Funciones */
int elf_validate(const struct elf_header *header);
u32 elf_load(const void *elf_data, u32 size);
int elf_execute(const char *filename);

#endif