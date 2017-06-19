#!/usr/bin/python

from pretty_dump import *

parse_fs('/tmp/dump')

print "Show vxlan rules"
for fte in ftes:
    if fte.is_vxlan:
        print fte
