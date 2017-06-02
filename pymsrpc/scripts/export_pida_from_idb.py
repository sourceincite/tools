#!/usr/bin/env python

'''
    export_pida_from_idb.py
    
    This will export a pida file for use in Paimei from a directory of idbs
    
    (c) 2007 Cody Pierce - See LICENSE.txt
'''

import sys, os, re

dir = sys.argv[1]

#os.chdir(dir)

files = os.listdir(dir)

for file in files:
    if not file.endswith("idb"):
        continue
    
    pida_path = dir + '\\' + file.split('.')[0] + ".pida"
    print "[*] Grabbing pida from %s" % (dir + "\\" + file)
    rc = os.system("\"C:\Program Files\IDA\idaw.exe\" -A -OIDAPython:pida_dump.py %s %s" % (pida_path, dir + '\\' + file))