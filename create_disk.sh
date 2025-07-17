#!/bin/bash

# Crear imagen de disco de 2MB
dd if=/dev/zero of=disk.img bs=512 count=4096

# Configurar Bochs (opcional)
echo "ata0: enabled=1, ioaddr1=0x1f0, ioaddr2=0x3f0, irq=14" > bochsrc.txt
echo "ata0-master: type=disk, path=\"disk.img\", mode=flat, cylinders=4, heads=16, spt=63" >> bochsrc.txt

echo "Disk image 'disk.img' created"
