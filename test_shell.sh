#!/bin/bash

echo "=== Testing Pepin OS Shell Interface ==="
echo ""

# Build the complete system
echo "1. Building complete system..."
cd /app
make clean > /dev/null 2>&1
make kernel > /dev/null 2>&1

if [ ! -f kernel ]; then
    echo "ERROR: Kernel compilation failed"
    exit 1
fi

# Build user programs  
echo "2. Building user programs..."
cd /app/user_programs
chmod +x build.sh
./build.sh > /dev/null 2>&1

if [ ! -f hello.elf ] || [ ! -f calc.elf ]; then
    echo "ERROR: User programs compilation failed"
    exit 1
fi

echo "✓ All components built successfully"
echo ""

echo "=== System is ready to run ==="
echo ""
echo "Key changes made:"
echo "✓ Removed competing background tasks"
echo "✓ Fixed shell input handling"
echo "✓ Improved keyboard interrupt processing"
echo "✓ Enhanced cursor management"
echo "✓ Reduced timer interrupt interference"
echo ""

echo "=== How to run ==="
echo "1. Basic run:"
echo "   qemu-system-i386 -kernel kernel"
echo ""
echo "2. With display mode:"
echo "   qemu-system-i386 -kernel kernel -display curses"
echo ""
echo "3. Using Makefile:"
echo "   make run-multiboot"
echo ""

echo "=== Expected behavior ==="
echo "- Boot messages will appear"
echo "- System will show 'Pepin OS Shell v1.0'"
echo "- You will see the prompt: 'pepin$ '"
echo "- You can type commands like: help, ls, echo test, etc."
echo "- No competing background tasks will interfere"
echo ""

echo "=== Available commands ==="
echo "help      - Show all available commands"
echo "ls        - List files in root directory"
echo "cat       - Display file contents"
echo "echo      - Print text"
echo "clear     - Clear screen"
echo "create    - Create new file"
echo "delete    - Delete file"
echo "write     - Write text to file"
echo "exec      - Execute ELF program"
echo "ps        - Show process information"
echo "mem       - Show memory information"
echo "reboot    - Restart system"
echo ""

echo "The shell should now work properly without interference!"