#!/usr/bin/env python2

my_file = open('jmp-esp-instructions.txt', 'r')
write_file = open('gold-adresses.txt', 'w')

file_in_list = my_file.readlines()

for ln in file_in_list:
	addr = ln.split('<')[0]
        new_addr = '\\x' + addr[8:10] +\
                   '\\x' + addr[6:8] +\
                   '\\x' + addr[4:6] +\
                   '\\x' + addr[2:4]

	write_file.write(new_addr+'\n')

my_file.close()
write_file.close()
