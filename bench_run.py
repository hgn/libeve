#!/usr/bin/env python

import os 
import subprocess

f = file('/tmp/epoll.dat', 'w')


for n in range(10, 100, 10):
    output = subprocess.Popen(["./bench", str(n)], stdout=subprocess.PIPE).communicate()[0]
    output_str = str(n) + " " + output.split()[0]
    print output_str
    f.write(output_str + "\n")

f.close()

f = file('/tmp/epoll.gpi', 'w')
gnuplot_template = """
set title "Accumulated Processing Duration"
set term postscript eps enhanced color "Times" 25
set style line 99 linetype 1 linecolor rgb "#000000" lw 2
set key left top
set key box linestyle 99
set key spacing 1.2
set grid xtics ytics mytics
set xlabel "Number of Descriptors"
set ylabel "Time [ns]"

set size 2
set size ratio 0.5
set style line 1 linetype 1 linecolor rgb "#4d8cbf" lw 6
set output "epoll.eps"
plot "/tmp/epoll.dat" using 1:2 title "epoll" ls 1

!epstopdf --outfile=epoll.pdf epoll.eps
!rm -rf epoll.eps
"""

f.write(gnuplot_template)
f.close

p = subprocess.Popen("gnuplot" + " /tmp/epoll.gpi", shell=True)
os.waitpid(p.pid, 0)

print "generated epoll.pdf"
