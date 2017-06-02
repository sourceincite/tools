#!/usr/bin/env python

'''
    midl_format_pointer_flags.py
    
    This just makes a comment about the midl format string pointer flags.
    
    (c) 2007 Cody Pierce - See LICENSE.txt
'''

# Format string pointer flags
AllocateAllNodes   = 0x01
DontFree           = 0x02
AllocOnStack       = 0x04
SimplePointer      = 0x08
PointerDeref       = 0x10

def get_pointer_flags(chary):
    chary &= 0x000000ff
    
    comment = "Pointer Flags: "
    
    if (chary & AllocateAllNodes): comment += "allocate all nodes, "
    if (chary & DontFree): comment += "dont free, "
    if (chary & AllocOnStack): comment += "alloc on stack, "
    if (chary & SimplePointer): comment += "simple pointer, "
    if (chary & PointerDeref): comment += "pointer deref, "
    
    return comment.rstrip().rstrip(',')
    
current_ea = ScreenEA()
chary = Byte(current_ea)
comment = get_pointer_flags(chary)

if not MakeComm(current_ea, comment):
    print "[!] Problem creating comment @ %08x %s" % (current_ea, comment)