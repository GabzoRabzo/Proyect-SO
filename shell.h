#ifndef SHELL_H
#define SHELL_H

#include "types.h"

/* Constantes del shell */
#define SHELL_BUFFER_SIZE 256
#define MAX_ARGS 16
#define MAX_ARG_LENGTH 64

/* Estructura de comando */
struct command {
    char name[32];
    void (*function)(int argc, char **argv);
    char description[128];
};

/* Funciones del shell */
void shell_init(void);
void shell_run(void);
void shell_parse_command(char *input);
int shell_split_args(char *input, char **args);

/* Comandos internos */
void cmd_help(int argc, char **argv);
void cmd_ls(int argc, char **argv);
void cmd_cat(int argc, char **argv);
void cmd_echo(int argc, char **argv);
void cmd_clear(int argc, char **argv);
void cmd_create(int argc, char **argv);
void cmd_delete(int argc, char **argv);
void cmd_write(int argc, char **argv);
void cmd_exec(int argc, char **argv);
void cmd_ps(int argc, char **argv);
void cmd_mem(int argc, char **argv);
void cmd_tasks(int argc, char **argv);
void cmd_reboot(int argc, char **argv);

/* Variables globales */
extern char shell_buffer[SHELL_BUFFER_SIZE];
extern int shell_buffer_pos;
extern struct command shell_commands[];
extern int shell_command_count;

#endif