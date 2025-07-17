/* Simple calculator program for Pepin OS */

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
    sys_print("Simple Calculator\n");
    sys_print("2 + 3 = 5\n");
    sys_print("10 - 4 = 6\n");
    sys_print("5 * 6 = 30\n");
    sys_print("Calculator finished.\n");
    sys_exit(0);
}