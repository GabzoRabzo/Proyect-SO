#ifndef _SYSCALL_H_
#define _SYSCALL_H_

#include "types.h"

/* Números de llamadas al sistema */
#define SYS_PRINT 1
#define SYS_EXIT 2
#define SYS_OPEN 3
#define SYS_CLOSE 4
#define SYS_READ 5
#define SYS_WRITE 6
#define SYS_CREATE 7
#define SYS_DELETE 8

/* Funciones */
void init_syscalls(void);
void do_syscalls(int sys_num);

#endif
