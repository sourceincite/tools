#!/usr/bin/env python

import sys

sys.path.append("..")

from ndr import *

def dump_ndr(ndr_object, level=0, count=0):
    gapchar = " "
    gaplen = 4
    gap = (gapchar * gaplen) * count
    
    if isinstance(ndr_object, ndr_unique):
        sys.stdout.write(gap)
        sys.stdout.write("type: %s\n" % ndr_object)
        dump_ndr(ndr_object.data, level=level, count=count+1)
        return
        
    sys.stdout.write(gap)
    sys.stdout.write("name: %s\n" % ndr_object.name)
    
    if isinstance(ndr_object, ndr_array_fixed) or isinstance(ndr_object, ndr_array_conformant) or isinstance(ndr_object, ndr_array_varying) or isinstance(ndr_object, ndr_array_conformant_varying):
        sys.stdout.write(gap)
        sys.stdout.write("type: %s\n" % (ndr_object))
        
        sys.stdout.write(gap)
        sys.stdout.write("count: %d\n" % (ndr_object.get_count()))
        
        dump_ndr(ndr_object.basetype, level=level, count=count+1)
    elif isinstance(ndr_object, ndr_struct):
        if ndr_object.defname:
            sys.stdout.write(gap)
            sys.stdout.write("dame: %s\n" % ndr_object.defname)
        
        sys.stdout.write(gap)
        sys.stdout.write("type: %s\n" % ndr_object)
        
        for element in ndr_object.elements:
            dump_ndr(element, level=level, count=count+1)
    elif isinstance(ndr_object, ndr_union):
        if ndr_object.defname:
            sys.stdout.write(gap)
            sys.stdout.write("dame: %s\n" % ndr_object.defname)

        sys.stdout.write(gap)
        sys.stdout.write("type: %s\n" % ndr_object)
        
        for case in ndr_object.elements.keys():
            thisgap = gap + (gapchar * gaplen)
            sys.stdout.write(thisgap)
            sys.stdout.write("case: %s\n" % case)
            
            dump_ndr(ndr_object.elements[case], level=level, count=count+1)
    else:
        sys.stdout.write(gap)
        sys.stdout.write("type: %s\n" % ndr_object)
        
        if level >= 1:
            sys.stdout.write(gap)
            sys.stdout.write("data: [%s]\n" % print_hex(ndr_object.get_packed()))
        
    sys.stdout.write("\n")
    
def print_hex(data):
    output = ""
    
    for char in data:
        output += "\\x%02x" % ord(char)
    
    return output