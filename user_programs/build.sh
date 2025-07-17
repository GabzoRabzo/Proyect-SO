#!/bin/bash

# Script para compilar programas de usuario
cd /app/user_programs

echo "Compilando programas de usuario..."

# Compilar hello.c
echo "Compilando hello.c..."
i686-linux-gnu-gcc -m32 -c -ffreestanding -fno-pic -fno-stack-protector -nostdlib -Wall hello.c -o hello.o
i686-linux-gnu-ld -m elf_i386 -Ttext=0x400000 --entry=_start hello.o -o hello.elf

# Compilar calc.c
echo "Compilando calc.c..."
i686-linux-gnu-gcc -m32 -c -ffreestanding -fno-pic -fno-stack-protector -nostdlib -Wall calc.c -o calc.o
i686-linux-gnu-ld -m elf_i386 -Ttext=0x400000 --entry=_start calc.o -o calc.elf

echo "Programas compilados:"
ls -la *.elf

echo "Copia los archivos .elf al sistema de archivos del OS usando el shell"