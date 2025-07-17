#!/usr/bin/env python3

import sys
import os

def binary_to_c(filename, array_name):
    with open(filename, 'rb') as f:
        data = f.read()
    
    # Generate C code
    c_code = f"""/* Generated from {filename} */
#include "../types.h"

const unsigned char {array_name}[] = {{
"""
    
    # Add bytes, 16 per line
    for i in range(0, len(data), 16):
        line = "    "
        for j in range(16):
            if i + j < len(data):
                line += f"0x{data[i + j]:02x}"
                if i + j < len(data) - 1:
                    line += ", "
        c_code += line + "\n"
    
    c_code += "};\n\n"
    c_code += f"const u32 {array_name}_size = sizeof({array_name});\n"
    
    return c_code

# Generate hello.elf data
hello_c = binary_to_c("/app/user_programs/hello.elf", "hello_elf_data")
with open("/app/user_programs/hello_elf_data.c", "w") as f:
    f.write(hello_c)

# Generate calc.elf data
calc_c = binary_to_c("/app/user_programs/calc.elf", "calc_elf_data")
with open("/app/user_programs/calc_elf_data.c", "w") as f:
    f.write(calc_c)

print("Generated hello_elf_data.c and calc_elf_data.c")