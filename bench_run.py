#!/usr/bin/env python

import os 
import subprocess

f = file('/tmp/epoll.dat', 'w')


for n in range(10, 500, 2):
    output = subprocess.Popen(["./bench", str(n)], stdout=subprocess.PIPE).communicate()[0]
    output_str = str(n) + " " + output.split()[0]
    print output_str
    f.write(output_str + "\n")

f.close()

