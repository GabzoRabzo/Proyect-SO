#!/bin/bash

# Script para generar datos ELF embebidos en el kernel
cd /app/user_programs

echo "Generando datos ELF embebidos..."

# Generar hello_elf_data.c
echo "/* Datos ELF embebidos para hello.elf */" > hello_elf_data.c
echo "#include \"../types.h\"" >> hello_elf_data.c
echo "" >> hello_elf_data.c
echo "const unsigned char hello_elf_data[] = {" >> hello_elf_data.c
xxd -i < hello.elf | sed 's/^/    /' >> hello_elf_data.c
echo "};" >> hello_elf_data.c
echo "" >> hello_elf_data.c
echo "const u32 hello_elf_size = sizeof(hello_elf_data);" >> hello_elf_data.c

# Generar calc_elf_data.c
echo "/* Datos ELF embebidos para calc.elf */" > calc_elf_data.c
echo "#include \"../types.h\"" >> calc_elf_data.c
echo "" >> calc_elf_data.c
echo "const unsigned char calc_elf_data[] = {" >> calc_elf_data.c
xxd -i < calc.elf | sed 's/^/    /' >> calc_elf_data.c
echo "};" >> calc_elf_data.c
echo "" >> calc_elf_data.c
echo "const u32 calc_elf_size = sizeof(calc_elf_data);" >> calc_elf_data.c

# Crear el header
echo "/* Headers para datos ELF embebidos */" > elf_data.h
echo "#ifndef ELF_DATA_H" >> elf_data.h
echo "#define ELF_DATA_H" >> elf_data.h
echo "" >> elf_data.h
echo "#include \"../types.h\"" >> elf_data.h
echo "" >> elf_data.h
echo "extern const unsigned char hello_elf_data[];" >> elf_data.h
echo "extern const u32 hello_elf_size;" >> elf_data.h
echo "extern const unsigned char calc_elf_data[];" >> elf_data.h
echo "extern const u32 calc_elf_size;" >> elf_data.h
echo "" >> elf_data.h
echo "#endif" >> elf_data.h

echo "Datos ELF generados en hello_elf_data.c y calc_elf_data.c"