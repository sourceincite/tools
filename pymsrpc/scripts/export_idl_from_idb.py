#!/usr/bin/env python

'''
    export_idl_from_idb.py
    
    This script will batch output an idl from any idbs in a directory containing rpc interfaces
    
    (c) 2007 Cody Pierce - See LICENSE.txt
'''

import sys, os, re

dir = sys.argv[1]

#os.chdir(dir)

files = os.listdir(dir)

for file in files:
    if not file.endswith("idb"):
        continue
    
    mida_path = dir + '\\' + file.split('.')[0] + ".idl"
    print "[*] Grabbing idl from %s" % (dir + "\\" + file)
    rc = os.system("\"C:\Program Files\IDA\idaw.exe\" -A -Smida.idc -Oofile:%s %s" % (mida_path, dir + '\\' + file))