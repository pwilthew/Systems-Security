#!/bin/sh

echo "Running... Be patient"
echo "b main" > gdb-commands.txt;
echo "r" >> gdb-commands.txt;
./printSeveralAddresses.py >> gdb-commands.txt;
gdb -batch -x gdb-commands.txt --args ./getscore > instructions.txt;
cat instructions.txt | tr -d " " | tr -d "\t" | grep ':jmp\*%esp' > jmp-esp-instructions.txt;
./findJmpEsp.py;

