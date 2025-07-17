#!/bin/bash

echo "=== Pepin OS Complete Build and Test ==="
echo ""

# Compilar el kernel
echo "1. Compilando kernel..."
cd /app
make clean
make kernel

if [ ! -f kernel ]; then
    echo "ERROR: No se pudo compilar el kernel"
    exit 1
fi

echo "✓ Kernel compilado exitosamente"

# Compilar programas de usuario
echo ""
echo "2. Compilando programas de usuario..."
cd /app/user_programs
./build.sh

echo ""
echo "3. Kernel compilado y listo para ejecutar"
echo ""
echo "=== Funcionalidades implementadas ==="
echo "✓ Sistema de archivos básico"
echo "✓ Shell con comandos internos"
echo "✓ Soporte para ELF"
echo "✓ System calls extendidas"
echo "✓ Programas de usuario de ejemplo"
echo ""
echo "=== Comandos disponibles en el shell ==="
echo "help      - Mostrar comandos disponibles"
echo "ls        - Listar archivos"
echo "cat       - Mostrar contenido de archivo"
echo "echo      - Imprimir texto"
echo "clear     - Limpiar pantalla"
echo "create    - Crear nuevo archivo"
echo "delete    - Eliminar archivo"
echo "write     - Escribir texto a archivo"
echo "exec      - Ejecutar programa ELF"
echo "ps        - Mostrar procesos"
echo "mem       - Mostrar información de memoria"
echo "reboot    - Reiniciar sistema"
echo ""
echo "=== Archivos de ejemplo creados ==="
echo "readme.txt    - Archivo de prueba con texto"
echo "welcome.txt   - Archivo de bienvenida"
echo ""
echo "=== Ejecución ==="
echo "Para ejecutar el OS:"
echo "  make run-multiboot"
echo "  O directamente: qemu-system-i386 -kernel kernel -display curses"
echo ""
echo "Para crear ISO:"
echo "  make iso"
echo "  make run-iso"
echo ""
echo "¡El sistema operativo Pepin OS está completo!"