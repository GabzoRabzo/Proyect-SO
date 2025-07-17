#include "types.h"
#include "lib.h"
#include "screen.h"
#include "io.h"
#include "fs.h"
#include "syscall.h"

void do_syscalls(int sys_num)
{
    char *u_str;
    int i;
    int fd;
    char *filename;
    void *buffer;
    u32 size;
    int result;

    switch (sys_num) {
        case SYS_PRINT:
            /* Obtener el puntero a la cadena desde el registro EBX */
            asm("mov %%ebx, %0": "=m"(u_str) :);
            
            /* Temporización para demostrar la preempción */
            for (i = 0; i < 100000; i++);
            
            /* Deshabilitar interrupciones durante la escritura para evitar corrupción */
            cli;
            
            /* Cambiar el color para mostrar que es output de usuario */
            u8 old_attr = kattr;
            kattr = 0x0A;  /* Verde brillante */
            
            print("user   : ");
            print(u_str);
            
            /* Restaurar el color original */
            kattr = old_attr;
            
            /* Rehabilitar interrupciones */
            sti;
            break;
            
        case SYS_EXIT:
            /* Terminar el proceso actual */
            print("Process exit\n");
            // En un OS real, aquí terminaríamos el proceso
            break;
            
        case SYS_OPEN:
            /* Abrir archivo */
            asm("mov %%ebx, %0": "=m"(filename) :);
            fd = fs_open_file(filename);
            asm("mov %0, %%eax": :"m"(fd) :);
            break;
            
        case SYS_CLOSE:
            /* Cerrar archivo */
            asm("mov %%ebx, %0": "=m"(fd) :);
            fs_close_file(fd);
            break;
            
        case SYS_READ:
            /* Leer archivo */
            asm("mov %%ebx, %0": "=m"(fd) :);
            asm("mov %%ecx, %0": "=m"(buffer) :);
            asm("mov %%edx, %0": "=m"(size) :);
            result = fs_read_file(fd, buffer, size);
            asm("mov %0, %%eax": :"m"(result) :);
            break;
            
        case SYS_WRITE:
            /* Escribir archivo */
            asm("mov %%ebx, %0": "=m"(fd) :);
            asm("mov %%ecx, %0": "=m"(buffer) :);
            asm("mov %%edx, %0": "=m"(size) :);
            result = fs_write_file(fd, buffer, size);
            asm("mov %0, %%eax": :"m"(result) :);
            break;
            
        case SYS_CREATE:
            /* Crear archivo */
            asm("mov %%ebx, %0": "=m"(filename) :);
            asm("mov %%ecx, %0": "=m"(size) :);
            result = fs_create_file(filename, size);
            asm("mov %0, %%eax": :"m"(result) :);
            break;
            
        case SYS_DELETE:
            /* Eliminar archivo */
            asm("mov %%ebx, %0": "=m"(filename) :);
            result = fs_delete_file(filename);
            asm("mov %0, %%eax": :"m"(result) :);
            break;
            
        default:
            print("syscall: unknown system call ");
            print_dec(sys_num);
            print("\n");
            break;
    }

    return;
}
