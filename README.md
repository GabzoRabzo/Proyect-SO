# Pepin OS - Sistema Operativo Completo

## Descripción
Pepin OS es un sistema operativo desarrollado siguiendo el tutorial de Michelizza, extendido con funcionalidades adicionales para crear un sistema operativo funcional completo.

## Funcionalidades Implementadas

### 1. Sistema Base (del tutorial original)
- ✅ **Bootloader Multiboot** - Compatible con GRUB
- ✅ **Gestión de Memoria** - Paginación, heap, protección de memoria
- ✅ **Multitarea** - Scheduler y cambio de contexto
- ✅ **Manejo de Interrupciones** - IDT, ISR, PIC
- ✅ **E/S Básica** - Pantalla, teclado, IDE

### 2. Nuevas Funcionalidades Implementadas

#### Sistema de Archivos
- **Directorio raíz** con hasta 64 archivos
- **Operaciones básicas**: crear, eliminar, leer, escribir
- **Almacenamiento en disco** usando controlador IDE
- **Descriptores de archivo** para archivos abiertos

#### Shell Interactivo
- **Prompt de comandos** (`pepin$ `)
- **Parser de argumentos** y procesamiento de comandos
- **12 comandos integrados**:
  - `help` - Mostrar comandos disponibles
  - `ls` - Listar archivos
  - `cat` - Mostrar contenido de archivo
  - `echo` - Imprimir texto
  - `clear` - Limpiar pantalla
  - `create` - Crear nuevo archivo
  - `delete` - Eliminar archivo
  - `write` - Escribir texto a archivo
  - `exec` - Ejecutar programa ELF
  - `ps` - Mostrar procesos
  - `mem` - Mostrar información de memoria
  - `reboot` - Reiniciar sistema

#### Soporte ELF
- **Cargador ELF** para ejecutables de 32 bits
- **Validación de headers** ELF
- **Carga de segmentos** en memoria
- **Ejecución de programas** de usuario

#### System Calls Extendidas
- `SYS_PRINT` - Imprimir texto
- `SYS_EXIT` - Terminar proceso
- `SYS_OPEN` - Abrir archivo
- `SYS_CLOSE` - Cerrar archivo
- `SYS_READ` - Leer de archivo
- `SYS_WRITE` - Escribir a archivo
- `SYS_CREATE` - Crear archivo
- `SYS_DELETE` - Eliminar archivo

#### Programas de Usuario
- **hello.c** - Programa "Hello World"
- **calc.c** - Calculadora simple
- **Compilación automática** a ELF

## Estructura del Proyecto

```
/app/
├── kernel.c           # Kernel principal
├── boot.asm           # Bootloader multiboot
├── screen.c/.h        # Manejo de pantalla
├── kbd.c/.h           # Controlador de teclado
├── gdt.c/.h           # Global Descriptor Table
├── idt.c/.h           # Interrupt Descriptor Table
├── isr.c              # Interrupt Service Routines
├── pic.c              # Programmable Interrupt Controller
├── mm.c/.h            # Gestión de memoria
├── task.c/.h          # Gestión de tareas
├── process.c/.h       # Gestión de procesos
├── schedule.c         # Scheduler
├── syscall.c/.h       # System calls
├── heap.c             # Heap manager
├── ide.c/.h           # Controlador IDE
├── fs.c/.h            # Sistema de archivos
├── elf.c/.h           # Cargador ELF
├── shell.c/.h         # Shell interactivo
├── lib.c/.h           # Funciones de librería
├── types.h            # Definiciones de tipos
├── io.h               # Macros de I/O
├── Makefile           # Sistema de construcción
└── user_programs/     # Programas de usuario
    ├── hello.c
    ├── calc.c
    └── build.sh
```

## Cómo Compilar y Ejecutar

### 1. Compilar el Kernel
```bash
cd /app
make clean
make kernel
```

### 2. Compilar Programas de Usuario
```bash
cd /app/user_programs
chmod +x build.sh
./build.sh
```

### 3. Ejecutar el OS

#### Opción 1: QEMU directo (Recomendado)
```bash
qemu-system-i386 -kernel kernel
```

#### Opción 2: Con display curses
```bash
qemu-system-i386 -kernel kernel -display curses
```

#### Opción 3: Usando Makefile
```bash
make run-multiboot
```

#### Opción 4: Crear ISO
```bash
make iso
make run-iso
```

### 4. Usar el Script de Prueba
```bash
chmod +x test_shell.sh
./test_shell.sh
```

## Uso del Sistema

### Al Bootear
1. El sistema inicializa todos los componentes
2. Carga el sistema de archivos
3. Crea archivos de ejemplo
4. Inicia el shell interactivo

### Comandos Básicos
```bash
pepin$ help                    # Mostrar ayuda
pepin$ ls                      # Listar archivos
pepin$ cat readme.txt          # Leer archivo
pepin$ echo Hello World        # Imprimir texto
pepin$ create test.txt 100     # Crear archivo de 100 bytes
pepin$ write test.txt "Hola"   # Escribir en archivo
pepin$ exec hello.elf          # Ejecutar programa
pepin$ ps                      # Ver procesos
pepin$ mem                     # Ver memoria
pepin$ tasks                   # Iniciar tareas de demostración
pepin$ reboot                  # Reiniciar
```

### Características Especiales
- **Shell Interactivo**: Interfaz limpia sin tareas en segundo plano
- **Multitarea Opcional**: Usa el comando `tasks` para activar demostración
- **Gestión de Archivos**: Crear, leer, escribir y eliminar archivos
- **Ejecución de Programas**: Soporte completo para ELF

## Características Técnicas

### Memoria
- **Paginación** habilitada
- **Heap dinámico** para kernel
- **Protección de memoria** básica
- **Gestión de páginas** física

### Procesos
- **Multitarea cooperativa**
- **Cambio de contexto** por timer
- **TSS** para cada tarea
- **Espacios de memoria** separados

### Sistema de Archivos
- **Almacenamiento en disco** IDE
- **Tabla de archivos** en memoria
- **Descriptores de archivo**
- **Operaciones síncronas**

### Interrupciones
- **Timer** para multitarea
- **Teclado** para entrada
- **System calls** vía int 0x30

## Limitaciones Actuales

- **No hay protección** entre procesos de usuario
- **Sistema de archivos** muy básico (sin directorios)
- **No hay red** ni otros dispositivos
- **Memoria limitada** para procesos
- **No hay bibliotecas** estándar para usuario

## Próximas Mejoras Posibles

1. **Protección de memoria** de usuario
2. **Sistema de archivos** jerárquico
3. **Bibliotecas estándar** C
4. **Drivers** adicionales
5. **Networking** básico
6. **GUI** simple

## Créditos

- Basado en el tutorial de **Michelizza** para Pepin OS
- Extendido con funcionalidades adicionales
- Desarrollado para aprendizaje de sistemas operativos