#include "ide.h"
#include "io.h"
#include "screen.h"
#include "lib.h"
#include "mm.h"

// Función para esperar a que el disco esté listo
static int ide_wait(int check_error) {
    u8 status;
    
    do {
        status = inb(IDE_STATUS);
    } while (status & IDE_STATUS_BSY);
    
    if (check_error && (status & IDE_STATUS_ERR)) {
        print("IDE    : Error during operation\n");
        return -1;
    }
    
    return 0;
}

// Inicialización del controlador IDE
void ide_init(void) {
    outb(IDE_DRIVE_HEAD, 0xE0 | (IDE_MASTER << 4)); // Seleccionar master
    outb(IDE_SECT_COUNT, 0);
    outb(IDE_SECT_NUM, 0);
    
    // Esperar a que el disco esté listo
    ide_wait(0);
    
    print("IDE    : Controller initialized\n");
}

// Leer sectores del disco
int ide_read_sectors(int drive, u32 lba, u8 num_sectors, void *buffer) {
    u16 *buf = (u16 *)buffer;
    int i;
    
    // Esperar a que el disco esté listo
    if (ide_wait(1)) return -1;
    
    // Configurar parámetros de lectura
    outb(IDE_DRIVE_HEAD, 0xE0 | (drive << 4) | ((lba >> 24) & 0x0F));
    outb(IDE_SECT_COUNT, num_sectors);
    outb(IDE_SECT_NUM, lba & 0xFF);
    outb(IDE_CYL_LOW, (lba >> 8) & 0xFF);
    outb(IDE_CYL_HIGH, (lba >> 16) & 0xFF);
    
    // Enviar comando de lectura
    outb(IDE_CMD, IDE_CMD_READ);
    
    // Leer datos sector por sector
    for (i = 0; i < num_sectors; i++) {
        // Esperar hasta que los datos estén listos
        if (ide_wait(1)) return -1;
        
        // Leer 256 palabras (512 bytes)
        insl(IDE_DATA, buf, 128);
        buf += 256;
    }
    
    return 0;
}

// Escribir sectores en el disco
int ide_write_sectors(int drive, u32 lba, u8 num_sectors, void *buffer) {
    u16 *buf = (u16 *)buffer;
    int i;
    
    // Esperar a que el disco esté listo
    if (ide_wait(1)) return -1;
    
    // Configurar parámetros de escritura
    outb(IDE_DRIVE_HEAD, 0xE0 | (drive << 4) | ((lba >> 24) & 0x0F));
    outb(IDE_SECT_COUNT, num_sectors);
    outb(IDE_SECT_NUM, lba & 0xFF);
    outb(IDE_CYL_LOW, (lba >> 8) & 0xFF);
    outb(IDE_CYL_HIGH, (lba >> 16) & 0xFF);
    
    // Enviar comando de escritura
    outb(IDE_CMD, IDE_CMD_WRITE);
    
    // Escribir datos sector por sector
    for (i = 0; i < num_sectors; i++) {
        // Esperar hasta que el disco esté listo para recibir datos
        if (ide_wait(1)) return -1;
        
        // Escribir 256 palabras (512 bytes)
        outsl(IDE_DATA, buf, 128);
        buf += 256;
    }
    
    // Esperar a que la escritura se complete
    if (ide_wait(1)) return -1;
    
    return 0;
}

// Identificar dispositivo IDE
int ide_identify(int drive, u16 *buffer) {
    // Esperar a que el disco esté listo
    if (ide_wait(1)) return -1;
    
    // Configurar parámetros de identificación
    outb(IDE_DRIVE_HEAD, 0xE0 | (drive << 4));
    outb(IDE_SECT_COUNT, 0);
    outb(IDE_SECT_NUM, 0);
    outb(IDE_CYL_LOW, 0);
    outb(IDE_CYL_HIGH, 0);
    
    // Enviar comando IDENTIFY
    outb(IDE_CMD, IDE_CMD_IDENTIFY);
    
    // Esperar respuesta
    if (ide_wait(1)) return -1;
    
    // Leer datos de identificación (256 palabras = 512 bytes)
    insl(IDE_DATA, buffer, 128);
    
    return 0;
}
