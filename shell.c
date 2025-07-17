#include "shell.h"
#include "screen.h"
#include "kbd.h"
#include "fs.h"
#include "elf.h"
#include "mm.h"
#include "process.h"
#include "task.h"
#include "lib.h"
#include "io.h"

/* Variables globales */
char shell_buffer[SHELL_BUFFER_SIZE];
int shell_buffer_pos = 0;

/* Tabla de comandos */
struct command shell_commands[] = {
    {"help", cmd_help, "Show available commands"},
    {"ls", cmd_ls, "List files in current directory"},
    {"cat", cmd_cat, "Display file contents"},
    {"echo", cmd_echo, "Display text"},
    {"clear", cmd_clear, "Clear screen"},
    {"create", cmd_create, "Create a new file"},
    {"delete", cmd_delete, "Delete a file"},
    {"write", cmd_write, "Write text to a file"},
    {"exec", cmd_exec, "Execute an ELF file"},
    {"ps", cmd_ps, "Show running processes"},
    {"mem", cmd_mem, "Show memory information"},
    {"tasks", cmd_tasks, "Start background demo tasks"},
    {"reboot", cmd_reboot, "Restart the system"}
};

int shell_command_count = sizeof(shell_commands) / sizeof(struct command);

/* Mostrar prompt */
void shell_show_prompt(void) {
    kattr = 0x0E;  // Yellow
    print("pepin$ ");
    kattr = 0x07;  // White
}

/* Inicializar el shell */
void shell_init(void) {
    shell_buffer_pos = 0;
    memset(shell_buffer, 0, SHELL_BUFFER_SIZE);
    
    kattr = 0x0A;  // Green
    print("\n");
    print("===================================\n");
    print("   Pepin OS Shell v1.0\n");
    print("===================================\n");
    print("Type 'help' for available commands\n");
    print("\n");
    kattr = 0x07;  // White
}

/* Ejecutar el shell */
void shell_run(void) {
    shell_show_prompt();
    
    while (1) {
        // Leer input del teclado
        char c = kbd_getchar();
        
        if (c == '\n' || c == '\r') {
            // Ejecutar comando
            print("\n");
            shell_buffer[shell_buffer_pos] = '\0';
            
            if (shell_buffer_pos > 0) {
                shell_parse_command(shell_buffer);
            }
            
            // Reiniciar buffer
            shell_buffer_pos = 0;
            memset(shell_buffer, 0, SHELL_BUFFER_SIZE);
            
            shell_show_prompt();
        } else if (c == '\b') {
            // Backspace
            if (shell_buffer_pos > 0) {
                shell_buffer_pos--;
                shell_buffer[shell_buffer_pos] = '\0';
                
                // Mover cursor hacia atrás y borrar carácter
                if (kX > 0) {
                    kX--;
                    putcar(' ');
                    kX--;
                    show_cursor();
                }
            }
        } else if (c >= 32 && c <= 126) {
            // Carácter imprimible
            if (shell_buffer_pos < SHELL_BUFFER_SIZE - 1) {
                shell_buffer[shell_buffer_pos] = c;
                shell_buffer_pos++;
                putcar(c);
            }
        }
    }
}

/* Parsear y ejecutar comando */
void shell_parse_command(char *input) {
    char *args[MAX_ARGS];
    int argc = shell_split_args(input, args);
    
    if (argc == 0) {
        return;
    }
    
    // Buscar comando
    for (int i = 0; i < shell_command_count; i++) {
        if (strcmp(args[0], shell_commands[i].name) == 0) {
            shell_commands[i].function(argc, args);
            return;
        }
    }
    
    // Comando no encontrado
    print("Shell  : Command not found: ");
    print(args[0]);
    print("\n");
}

/* Dividir argumentos */
int shell_split_args(char *input, char **args) {
    int argc = 0;
    int i = 0;
    int arg_start = 0;
    int in_arg = 0;
    
    while (input[i] != '\0' && argc < MAX_ARGS) {
        if (input[i] == ' ' || input[i] == '\t') {
            if (in_arg) {
                // Fin del argumento
                input[i] = '\0';
                args[argc] = &input[arg_start];
                argc++;
                in_arg = 0;
            }
        } else {
            if (!in_arg) {
                // Inicio del argumento
                arg_start = i;
                in_arg = 1;
            }
        }
        i++;
    }
    
    // Último argumento
    if (in_arg && argc < MAX_ARGS) {
        args[argc] = &input[arg_start];
        argc++;
    }
    
    return argc;
}

/* Función auxiliar para comparar strings - ahora está en lib.c */

/* Comando: help */
void cmd_help(int argc, char **argv) {
    print("Available commands:\n");
    print("==================\n");
    
    for (int i = 0; i < shell_command_count; i++) {
        print(shell_commands[i].name);
        
        // Pad with spaces
        int name_len = strlen(shell_commands[i].name);
        for (int j = name_len; j < 12; j++) {
            print(" ");
        }
        
        print("- ");
        print(shell_commands[i].description);
        print("\n");
    }
}

/* Comando: ls */
void cmd_ls(int argc, char **argv) {
    fs_list_files();
}

/* Comando: cat */
void cmd_cat(int argc, char **argv) {
    if (argc < 2) {
        print("Usage: cat <filename>\n");
        return;
    }
    
    int fd = fs_open_file(argv[1]);
    if (fd < 0) {
        print("Cannot open file: ");
        print(argv[1]);
        print("\n");
        return;
    }
    
    // Reset file position to beginning before reading
    if (fd >= 0 && fd < MAX_FILES && open_files[fd].used) {
        open_files[fd].position = 0;
    }
    
    char *buffer = (char *)kmalloc(4096);
    if (buffer == NULL) {
        print("Cannot allocate memory\n");
        fs_close_file(fd);
        return;
    }
    
    int bytes_read = fs_read_file(fd, buffer, 4095);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        print(buffer);
        print("\n");
    } else {
        print("File is empty or cannot read file\n");
    }
    
    kfree(buffer);
    fs_close_file(fd);
}

/* Comando: echo */
void cmd_echo(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        print(argv[i]);
        if (i < argc - 1) {
            print(" ");
        }
    }
    print("\n");
}

/* Comando: clear */
void cmd_clear(int argc, char **argv) {
    clear_screen();
}

/* Comando: create */
void cmd_create(int argc, char **argv) {
    if (argc < 3) {
        print("Usage: create <filename> <size>\n");
        return;
    }
    
    // Convertir string a número (simple)
    u32 size = 0;
    char *size_str = argv[2];
    while (*size_str) {
        if (*size_str >= '0' && *size_str <= '9') {
            size = size * 10 + (*size_str - '0');
        }
        size_str++;
    }
    
    if (fs_create_file(argv[1], size) >= 0) {
        print("File created: ");
        print(argv[1]);
        print("\n");
    } else {
        print("Cannot create file: ");
        print(argv[1]);
        print("\n");
    }
}

/* Comando: delete */
void cmd_delete(int argc, char **argv) {
    if (argc < 2) {
        print("Usage: delete <filename>\n");
        return;
    }
    
    if (fs_delete_file(argv[1]) == 0) {
        print("File deleted: ");
        print(argv[1]);
        print("\n");
    } else {
        print("Cannot delete file: ");
        print(argv[1]);
        print("\n");
    }
}

/* Comando: write */
void cmd_write(int argc, char **argv) {
    if (argc < 3) {
        print("Usage: write <filename> <text>\n");
        return;
    }
    
    int fd = fs_open_file(argv[1]);
    if (fd < 0) {
        print("Cannot open file: ");
        print(argv[1]);
        print("\n");
        return;
    }
    
    // Reset file position to beginning before writing
    if (fd >= 0 && fd < MAX_FILES && open_files[fd].used) {
        open_files[fd].position = 0;
    }
    
    // Concatenar todos los argumentos después del filename
    char *text = argv[2];
    int text_len = strlen(text);
    
    if (fs_write_file(fd, text, text_len) == text_len) {
        print("Text written to ");
        print(argv[1]);
        print("\n");
    } else {
        print("Cannot write to file: ");
        print(argv[1]);
        print("\n");
    }
    
    fs_close_file(fd);
}

/* Comando: exec */
void cmd_exec(int argc, char **argv) {
    if (argc < 2) {
        print("Usage: exec <filename>\n");
        return;
    }
    
    elf_execute(argv[1]);
}

/* Comando: ps */
void cmd_ps(int argc, char **argv) {
    print("Process information:\n");
    print("Current processes: ");
    print_dec(n_proc);
    print("\n");
    
    for (int i = 0; i < n_proc; i++) {
        print("Process ");
        print_dec(i);
        print(": PID ");
        print_dec(p_list[i].pid);
        print("\n");
    }
}

/* Comando: mem */
void cmd_mem(int argc, char **argv) {
    print("Memory information:\n");
    print("Heap start: 0x");
    print_hex(HEAP_START);
    print("\n");
    print("Page heap start: 0x");
    print_hex(PAGE_HEAP_START);
    print("\n");
    
    // Mostrar algunos datos del heap
    print("Heap status: Active\n");
}

/* Comando: tasks */
void cmd_tasks(int argc, char **argv) {
    if (n_proc > 0) {
        print("Background tasks are already running\n");
        return;
    }
    
    print("Starting background demo tasks...\n");
    
    /* Cargar múltiples tareas */
    load_task((u32*)0x100000, (u32*)&task1, 0x2000);
    load_task((u32*)0x200000, (u32*)&task2, 0x2000);
    load_task((u32*)0x300000, (u32*)&task3, 0x2000);
    
    print("Background tasks loaded: ");
    print_dec(n_proc);
    print("\n");
    print("Note: Tasks will run in background and display output\n");
}

/* Comando: reboot */
void cmd_reboot(int argc, char **argv) {
    print("Rebooting system...\n");
    
    // Reiniciar usando el keyboard controller
    outb(0x64, 0xFE);
    
    // Si no funciona, bucle infinito
    while (1) {
        asm("hlt");
    }
}