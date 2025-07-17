#!/bin/bash

# Script para convertir binarios a código C
cd /app/user_programs

echo "Convertiendo archivos ELF a código C..."

# Función para generar array de bytes C
generate_c_array() {
    local file=$1
    local name=$2
    local output_file=$3
    
    echo "/* Generated from $file */" > $output_file
    echo "#include \"../types.h\"" >> $output_file
    echo "" >> $output_file
    echo "const unsigned char ${name}_data[] = {" >> $output_file
    
    od -t x1 -An $file | tr -d '\n' | sed 's/ /,0x/g' | sed 's/^,/    /' | sed 's/$//' >> $output_file
    
    echo "" >> $output_file
    echo "};" >> $output_file
    echo "" >> $output_file
    echo "const u32 ${name}_size = sizeof(${name}_data);" >> $output_file
}

# Generar datos para hello.elf
generate_c_array "hello.elf" "hello_elf" "hello_elf_data.c"

# Generar datos para calc.elf
generate_c_array "calc.elf" "calc_elf" "calc_elf_data.c"

echo "Archivos generados: hello_elf_data.c y calc_elf_data.c"