#!/bin/bash

echo "=== Testing GRUB Multiboot Kernel ==="

# Compilar el kernel
echo "1. Compilando kernel..."
make clean
make kernel

if [ ! -f kernel ]; then
    echo "ERROR: No se pudo compilar el kernel"
    exit 1
fi

echo "✓ Kernel compilado exitosamente"

# Verificar multiboot
echo "2. Verificando compatibilidad Multiboot..."
if command -v mbchk &> /dev/null; then
    mbchk kernel
    echo "✓ Verificación Multiboot completada"
else
    echo "⚠ mbchk no disponible, saltando verificación"
fi

# Mostrar símbolos
echo "3. Mostrando símbolos del kernel..."
nm -n kernel | head -20

echo ""
echo "=== Opciones de testing ==="
echo "a) Probar con QEMU (multiboot directo):"
echo "   make run-multiboot"
echo ""
echo "b) Crear ISO con GRUB2 y probar:"
echo "   make iso"
echo "   make run-iso"
echo ""
echo "c) Probar directamente:"
echo "   qemu-system-i386 -kernel kernel"
echo ""

# Preguntar si quiere probar automáticamente
read -p "¿Quieres probar el kernel ahora? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Ejecutando kernel con QEMU..."
    qemu-system-i386 -kernel kernel
fi
