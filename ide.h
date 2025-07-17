#ifndef IDE_H
#define IDE_H

#include "types.h"

// Puertos del controlador IDE primario
#define IDE_DATA        0x1F0
#define IDE_ERROR       0x1F1
#define IDE_SECT_COUNT  0x1F2
#define IDE_SECT_NUM    0x1F3
#define IDE_CYL_LOW     0x1F4
#define IDE_CYL_HIGH    0x1F5
#define IDE_DRIVE_HEAD  0x1F6
#define IDE_STATUS      0x1F7
#define IDE_CMD         0x1F7

// Bits del registro de estado
#define IDE_STATUS_ERR  0x01
#define IDE_STATUS_DRQ  0x08
#define IDE_STATUS_BSY  0x80

// Comandos
#define IDE_CMD_READ    0x20
#define IDE_CMD_WRITE   0x30
#define IDE_CMD_IDENTIFY 0xEC

// Tipos de unidad
#define IDE_MASTER      0
#define IDE_SLAVE       1

// Prototipos de funciones
void ide_init(void);
int ide_read_sectors(int drive, u32 lba, u8 num_sectors, void *buffer);
int ide_write_sectors(int drive, u32 lba, u8 num_sectors, void *buffer);
int ide_identify(int drive, u16 *buffer);

#endif
