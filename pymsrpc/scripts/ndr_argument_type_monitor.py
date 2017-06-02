#!/usr/bin/env python

'''
    ndr_argument_type_monitor.py
    
    This is kind of cheesy but it uses pydbg to load a hit of bad_stub_data points and
    ndr unmarshalling bps from 2k/xp and outputs the back trace so you can debug problems
    in the pymsrpc ndr routines.
    
    (c) 2007 Cody Pierce - See LICENSE.txt
'''

######################################################################
#
# Includes
#
######################################################################

import sys
import os
import struct
import time

sys.path.append(r's:\shared\paimei\trunk')
sys.path.append(r'c:\vmfarm\shared\paimei\trunk')

from pydbg import *
from pydbg.defines import *

handlers = [
'NdrUDTSimpleTypeUnmarshall1',
'NdrUDTSimpleTypeUnmarshall1',
'NdrUDTSimpleTypeUnmarshall1',
'NdrUDTSimpleTypeUnmarshall1',
'NdrUDTSimpleTypeUnmarshall1',
'NdrUDTSimpleTypeUnmarshall1',
'NdrUDTSimpleTypeUnmarshall1',
'NdrUDTSimpleTypeUnmarshall1',
'NdrUDTSimpleTypeUnmarshall1',
'NdrUDTSimpleTypeUnmarshall1',
'NdrUDTSimpleTypeUnmarshall1',
'NdrUDTSimpleTypeUnmarshall1',
'NdrUDTSimpleTypeUnmarshall1',
'NdrUDTSimpleTypeUnmarshall1',
'NdrUDTSimpleTypeUnmarshall1',
'NdrUDTSimpleTypeUnmarshall1',
'NdrUDTSimpleTypeUnmarshall1',
'NdrPointerUnmarshall',
'NdrPointerUnmarshall',
'NdrPointerUnmarshall',
'NdrPointerUnmarshall',
'NdrSimpleStructUnmarshall',
'NdrSimpleStructUnmarshall',
'NdrConformantStructUnmarshall',
'NdrConformantStructUnmarshall',
'NdrConformantVaryingStructUnmarshall',
'NdrComplexStructUnmarshall',
'NdrConformantArrayUnmarshall',
'NdrConformantVaryingArrayUnmarshall',
'NdrFixedArrayUnmarshall',
'NdrFixedArrayUnmarshall',
'NdrVaryingArrayUnmarshall',
'NdrVaryingArrayUnmarshall',
'NdrComplexArrayUnmarshall',
'NdrConformantStringUnmarshall',
'NdrConformantStringUnmarshall',
'NdrConformantStringUnmarshall',
'NdrConformantStringUnmarshall',
'NdrNonConformantStringUnmarshall',
'NdrNonConformantStringUnmarshall',
'NdrNonConformantStringUnmarshall',
'NdrNonConformantStringUnmarshall',
'NdrEncapsulatedUnionUnmarshall',
'NdrNonEncapsulatedUnionUnmarshall',
'NdrByteCountPointerUnmarshall',
'NdrXmitOrRepAsUnmarshall',
'NdrXmitOrRepAsUnmarshall',
'NdrPointerUnmarshall',
'NdrUnmarshallHandle']

######################################################################
#
# Our function breakpoint handlers
#
######################################################################

def handler_breakpoint(dbg):
    if dbg.first_breakpoint:
        sys.stdout.write("[*] Setting argument breakpoints...")
        for bp in dbg.rpc_arg_breakpoints:
            dbg.bp_set(bp, handler=rpc_arg_breakpoint)
        sys.stdout.write("Done.\n")
        
        sys.stdout.write("[*] Setting bad stub data breakpoints...")
        for bp in dbg.rpc_bad_stub_data_breakpoints:
            dbg.bp_set(bp, handler=rpc_bad_stub_data_breakpoint)
        sys.stdout.write("Done.\n")
        
        sys.stdout.write("[*] Setting good stub data breakpoints...")
        for bp in dbg.rpc_good_stub_data_breakpoints.values():
            dbg.bp_set(bp, handler=rpc_good_stub_data_breakpoint)
        sys.stdout.write("Done.\n")
        
    return DBG_CONTINUE

def rpc_arg_breakpoint(dbg):
    global handlers
    
    if dbg.targetos == "2000":
        type_num = dbg.context.Ecx & 0x3f
    else:
        type_num = dbg.context.Edx & 0x3f
    
    if not dbg.rpc_export_on:
        set_rpc_export_breakpoints(dbg, on=True)
        
    if dbg.rpc_function_args > 6:
        print "[!] Problem in playland more than 6 function_args"
        dbg.detach()
        sys.exit(-1)
        
    sys.stdout.write("[*] Calling %s for arg %d ndr_type 0x%x...\n" % (handlers[type_num], dbg.rpc_function_args, type_num))
        
    dbg.rpc_function_args += 1
    
    return DBG_CONTINUE

def rpc_bad_stub_data_breakpoint(dbg):
    sys.stdout.write("Failed.\n")
    
    dbg.rpc_function_args = 0
    set_rpc_export_breakpoints(dbg, on=False)
    
    return DBG_CONTINUE

def rpc_export_unmarshal_breakpoint(dbg):
    address = dbg.exception_address
    
    if address in dbg.rpc_export_unmarshall_breakpoints:
        sys.stdout.write("    %s\n" % dbg.rpc_export_unmarshall_breakpoints[address])
    
    return DBG_CONTINUE
    
def rpc_good_stub_data_breakpoint(dbg):
    address = dbg.exception_address
    
    sys.stdout.write("Success.\n")
    
    if dbg.rpc_good_stub_data_breakpoints["arg"] == address:
        dbg.rpc_function_args += 1
    elif dbg.rpc_good_stub_data_breakpoints["function"] == address:
        dbg.rpc_function_args = 0
        set_rpc_export_breakpoints(dbg, on=False)
        
    return DBG_CONTINUE

######################################################################
#
# Various helper routines
#
######################################################################

def set_rpc_export_breakpoints(dbg, on=True):
    if on:
        for bp in dbg.rpc_export_unmarshall_breakpoints.keys():
            dbg.bp_set(bp, handler=rpc_export_unmarshal_breakpoint)
        
        dbg.rpc_export_on = True
    else:
        for bp in dbg.rpc_export_unmarshall_breakpoints.keys():
            dbg.bp_del(bp)
        
        dbg.rpc_export_on = False
            
######################################################################
#
# Various set up routines before exection
#
######################################################################

def attach_target_proc(dbg, mypid):
    print "[*] Trying to attach to existing %s" % mypid
    for (pid, name) in dbg.enumerate_processes():
        if mypid == pid:
            try:
                print "[*] Attaching to %s (%d)" % (name, pid)
                dbg.attach(pid)
            except:
                print "[!] Problem attaching to %s" % name
                
                return False
            
            return True
            
    return False

######################################################################
#
# Builds out bp lists
#
######################################################################
def get_arg_breakpoints(targetos):
    if targetos == "2000":
        #.orpc:77D968AC 258 FF+        call    dword ptr [eax+ecx*4]
        bps = [0x77D968AC]
    else:
        #.text:77E7A02A 02C FF+        call    ds:UnmarshallRoutinesTable[edx*4]
        bps = [0x77E7A02A]
    
    return bps

def get_export_unmarshall_breakpoints(filename):
    bps = {}
    fh = open(filename, 'r')
    lines = fh.readlines()
    
    for line in lines:
        (name, bp) = line.split(",")
        if name:
            bps[int(bp.strip(), 16)] = name
    
    fh.close()
    
    return bps
    
def get_bad_stub_data_breakpoints(filename):
    bps = []
    fh = open(filename, 'r')
    lines = fh.readlines()
    
    for line in lines:
        bps.append(int(line, 16))
    
    fh.close()
    
    return bps

def get_good_stub_data_breakpoints(targetos):
    if targetos == "2000":
        #.orpc:77D96486 008 C9         leave
        #.orpc:77D968AF 258 8B+        mov     eax, [ebp+var_1FC]
        bps = {"function": 0x77D96486, "arg": 0x77D968AF}
    else:
        #.orpc:77EF3180 3DC 8D+        lea     eax, [ebp+pStubMsg]
        #.text:77E7A031 02C 83+        and     dword ptr [esi+24h], 0
        bps = {"arg": 0x77EF3180, "function": 0x77E7A031}
    
    return bps
    
######################################################################
#
# Command line arguments
#
######################################################################

if len(sys.argv) < 5:
    print "Usage: %s <pid> <bad stub file> <export unmarshall list> <2000|xp>" % sys.argv[0]
    
    sys.exit(-1)

procname = int(sys.argv[1])
bsf = sys.argv[2]
euf = sys.argv[3]
targetos = sys.argv[4].lower()

dbg = pydbg()
dbg.targetos = targetos
dbg.rpc_function_args = 0
dbg.rpc_export_on = False
dbg.rpc_arg_breakpoints = get_arg_breakpoints(targetos)
dbg.rpc_bad_stub_data_breakpoints = get_bad_stub_data_breakpoints(bsf)
dbg.rpc_export_unmarshall_breakpoints = get_export_unmarshall_breakpoints(euf)
dbg.rpc_good_stub_data_breakpoints = get_good_stub_data_breakpoints(targetos)

dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)

if not attach_target_proc(dbg, procname):
    print "[!] Couldnt load/attach to %s" % procname
    
    sys.exit(-1)

dbg.debug_event_loop()