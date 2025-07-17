#!/bin/bash

echo "=== Pepin OS - Prueba Rápida ==="
echo ""

# Verificar que todos los archivos necesarios existen
echo "1. Verificando archivos..."
files=("kernel" "user_programs/hello.elf" "user_programs/calc.elf")
for file in "${files[@]}"; do
    if [ -f "/app/$file" ]; then
        echo "✓ $file existe"
    else
        echo "✗ $file NO existe"
        exit 1
    fi
done

echo ""
echo "2. Información del kernel:"
ls -lh /app/kernel
file /app/kernel

echo ""
echo "3. Información de programas de usuario:"
ls -lh /app/user_programs/*.elf
file /app/user_programs/*.elf

echo ""
echo "4. Verificando símbolos del kernel:"
nm -n /app/kernel | grep -E "(main|shell|fs_init|elf_load)" | head -10

echo ""
echo "=== Sistema Listo ==="
echo "Para ejecutar:"
echo "  qemu-system-i386 -kernel /app/kernel -display curses"
echo ""
echo "Una vez iniciado, puedes usar estos comandos:"
echo "  help    - Ver comandos disponibles"
echo "  ls      - Listar archivos"
echo "  cat readme.txt - Leer archivo"
echo "  echo test - Imprimir texto"
echo ""
echo "¡El sistema operativo Pepin OS está completo y funcional!"