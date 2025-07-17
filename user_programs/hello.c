/* Hello World program for Pepin OS */

void sys_print(const char *str) {
    asm volatile("movl $1, %%eax;"
                 "movl %0, %%ebx;"
                 "int $0x30"
                 :
                 : "m"(str)
                 : "eax", "ebx");
}

void sys_exit(int code) {
    asm volatile("movl $2, %%eax;"
                 "movl %0, %%ebx;"
                 "int $0x30"
                 :
                 : "m"(code)
                 : "eax", "ebx");
}

void _start() {
    sys_print("Hello from user program!\n");
    sys_print("This is a simple ELF program running in Pepin OS.\n");
    sys_exit(0);
}