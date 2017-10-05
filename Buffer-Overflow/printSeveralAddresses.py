#!/usr/bin/env python2
addr = 0x42000000
finaladdr = 0x42130b3c

for i in range(addr, finaladdr):
	print "x/i " + hex(i)
