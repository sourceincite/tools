
'''
    parse.py
    
    A parser for lexing and building ndr data types from a supplied IDL.
    
    (c) 2007 Cody Pierce, Aaron Portnoy - BSD License - See LICENSE.txt
'''

# Python imports
import sys, re, copy

# Plex imports
try:
    from plex import *
except ImportError:
    print '[!] Problem importing Plex library please make sure you have this installed'
    print '[!] http://www.cosc.canterbury.ac.nz/greg.ewing/python/Plex/'
    sys.exit(-1)

# Pymsrpc imports
import lexer
from ndr import *

# debug mode
DEBUG = False


##############################################################################################
class GLOBALS:
    def __init__(self, defined={}, undefined={}):
        self.defined   = defined
        self.undefined = undefined

##############################################################################################
class idl_UUID:
    def __init__(self, ifid="", version="", opcodes=[], objects=[]):
        self.ifid = ifid
        self.version = version
        self.opcodes = opcodes
        self.objects = objects

##############################################################################################        
class idl_opcode:
    def __init__(self, opnum="", address="", elements=[]):
        self.opnum = int(opnum, 16)
        self.address = address
        self.elements = elements
        
    def get_packed(self):
        packeddata = ""
        for elem in self.elements:
            packeddata += elem.get_packed()

        return packeddata

##############################################################################################
def abort(msg=""):
    if not msg == "":
        print("[!] ABORTING! %s" % msg)
        sys.exit(1)
    else:
        print("[!] ABORTING! No error message provided.")
        sys.exit(1)

##############################################################################################
def dump_list(ndr_list, debug=False):
    for elem in ndr_list.keys():
        print "[%s] [%s]" % (elem, ndr_list[elem])
        
        if debug:
            dump_ndr(ndr_list[elem])

##############################################################################################
def deref_ndr(ndr):
    # Re-entrant so we can do any level of deref
    if isinstance(ndr, ndr_array_conformant) or isinstance(ndr, ndr_array_varying) or isinstance(ndr, ndr_array_conformant_varying) or isinstance(ndr, ndr_array_fixed):
        if ndr.basetype:
            return deref_ndr(ndr.basetype)
        else:
            abort("[!] Problem with ndr_array deref")
    elif isinstance(ndr, ndr_unique):
        if ndr.data:
            return deref_ndr(ndr.data)
        else:
            abort("[!] Problem with ndr_unique deref")
    else:
        return ndr
    
##############################################################################################
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
        
##############################################################################################
def get_array(basetype, size_is, max_is, length_is, first_is, last_is, fixed_num):
    array_type = None
    maxcount = None
    passed = None
    count = None
    
    cmod = None
    cptr = None
    
    mmod = None
    mptr = None
    
    pmod = None
    pptr = None
    
    # Need to see if its an array
    if (size_is or max_is) and (not length_is and not first_is and not last_is):
        array_type = "conformant"
        
        if size_is and not max_is:
            maxcount = size_is
        elif max_is and not size_is:
            maxcount = max_is
        else:
            # BUG
            maxcount = length_is
        
        maxcount = re.compile('.*\((.*)\)').split(maxcount)[1]
        
        # There has to be a better way?
        if re.compile("^\*[\w|\d]").match(maxcount):
            mptr = 1 
            maxcount = maxcount.lstrip("*")
        elif re.compile("^\*\*[\w|\d]").match(maxcount):
            mptr = 2
            maxcount = maxcount.lstrip("*")
                        
        if maxcount.count("/"):
            mc, mod = maxcount.split("/")
            
            maxcount = mc
            mmod = ("/", int(mod))
        elif maxcount.count("*"):
            mc, mod = maxcount.split("*")
            
            maxcount = mc
            mmod = ("*", int(mod))
        
        if re.compile(".*callback.*").match(maxcount):
            maxcount = 4
            
        if DEBUG:
            print "[*] Found conformant array"
                
        basetype = ndr_array_conformant(basetype=basetype, count=maxcount, cmod=mmod, cptr=mptr)
    elif (length_is or first_is or last_is) and (not size_is and not max_is):
        array_type = "varying"
        
        if length_is and not first_is and not last_is:
            passed = length_is
        elif first_is and not length_is and not last_is:
            passed = first_is
        elif last_is and not length_is and not first_is:
            passed = last_is
        elif first_is and last_is and not length_is:
            passed = first_is
        else:
            passed = length_is
        
        passed = re.compile('.*\((.*)\)').split(passed)[1]
        
        if re.compile("^\*[\w|\d]").match(passed):
            pptr = 1 
            passed = passed.lstrip("*")
        elif re.compile("^\*\*[\w|\d]").match(passed):
            pptr = 2
            passed = passed.lstrip("*")
                        
        if passed.count("/"):
            pc, mod = passed.split("/")
            
            passed = pc
            pmod = ("/", int(mod))
        elif maxcount.count("*"):
            pc, mod = passed.split("*")
            
            passed = pc
            pmod = ("*", int(mod))
        
        if DEBUG:
            print "[*] Found varying array"
                    
        basetype = ndr_array_varying(basetype=basetype, count=passed, cmod=pmod, cptr=pptr)
    elif (size_is or max_is) and (length_is or first_is or last_is):
        array_type = "conformant varying"
                
        if size_is and not max_is:
            maxcount = size_is
        elif max_is and not size_is:
            maxcount = max_is
        else:
            maxcount = length_is
        
        if length_is and not first_is and not last_is:
            passed = length_is
        elif first_is and not length_is and not last_is:
            passed = first_is
        elif last_is and not length_is and not first_is:
            passed = last_is
        elif first_is and last_is and not length_is:
            passed = first_is
        else:
            passed = length_is
        
        maxcount = re.compile('.*\((.*)\)').split(maxcount)[1]
        
        if re.compile("^\*[\w|\d]").match(maxcount):
            mptr = 1 
            maxcount = maxcount.lstrip("*")
        elif re.compile("^\*\*[\w|\d]").match(maxcount):
            mptr = 2
            maxcount = maxcount.lstrip("*")
                        
        if maxcount.count("/"):
            mc, mod = maxcount.split("/")
            
            maxcount = mc
            mmod = ("/", int(mod))
        elif maxcount.count("*"):
            mc, mod = maxcount.split("*")
            
            maxcount = mc
            mmod = ("*", int(mod))
            
        passed = re.compile('.*\((.*)\)').split(passed)[1]
        
        if re.compile("^\*[\w|\d]").match(passed):
            pptr = 1 
            passed = passed.lstrip("*")
        elif re.compile("^\*\*[\w|\d]").match(passed):
            pptr = 2
            passed = passed.lstrip("*")
                        
        if passed.count("/"):
            pc, mod = passed.split("/")
            
            passed = pc
            pmod = ("/", int(mod))
        elif maxcount.count("*"):
            pc, mod = passed.split("*")
            
            passed = pc
            pmod = ("*", int(mod))
        
        if DEBUG:
            print "[*] Found conformant varying array"
        
        basetype = ndr_array_conformant_varying(basetype=basetype, maxcount=maxcount, mmod=mmod, mptr=mptr, passed=passed, pmod=pmod, pptr=pptr)
    elif fixed_num:
        array_type = "fixed"

        if DEBUG:
            print "[*] Found fixed array"
            
        basetype = ndr_array_fixed(basetype=basetype, count=fixed_num)

    return basetype
    
##############################################################################################
def parse_opcode(token, opnum, address, scanner, global_info):
    '''
    Parses an IDL opcode
    '''

    if DEBUG:
        print "[*] Parsing opcode %s" % opnum

        print "------------------------"

    elements = []
    opcode_out = None
    
    direction = None
    
    unique = False
    ptr    = False
    ref    = False
    single = False
    double = False
    triple = False
    
    string = False
    context_handle = False
    
    array_type = None
    
    range = None
    fixed_num = None
    size_is = None
    length_is = None
    first_is = None
    last_is = None
    max_is = None
    
    switch_is = None
    
    basetype = None
    name = None
    
    ndr_type = None
    
    # Im in opcode state
    while True:
        if token[0] == "opcode_end":
            #print "[*] Ending opcode block"
            
            break
        elif token[0] == "opcode_element_end":
            #print "[*] Ending opcode element"
            
            # Skipping out shit
            if direction == "out":
                # We need to keep track of any [out] context_handles so we can run them first
                if context_handle:
                    print "[*] Adding context handle [out]"
                    opcode_out = ndr_context_handle()
                    
                if DEBUG:
                    print "[*] ..."
                
                token = scanner.read()
                
                context_handle = False
                
                continue
                    
            if size_is or length_is or first_is or last_is or max_is or fixed_num and not string:
                basetype = get_array(basetype, size_is, max_is, length_is, first_is, last_is, fixed_num)

            if isinstance(basetype, ndr_void) and context_handle:
                basetype = ndr_context_handle()
                    
            if string:
                if fixed_num and isinstance(basetype, ndr_wchar):
                    basetype = ndr_wstring_nonconformant(size=fixed_num)
                elif fixed_num and isinstance(basetype, ndr_char):
                    basetype = ndr_string_nonconformant(size=fixed_num)
                elif isinstance(basetype, ndr_wchar):
                    basetype = ndr_wstring()
                elif isinstance(basetype, ndr_char):
                    basetype = ndr_string()

            if not basetype:
                abort("[!] Got None basetype")
                token = scanner.read()
                continue
                
            basetype.name = name
                
            if unique:
                basetype = ndr_unique(data=basetype, name=basetype.name)
            
            if ptr:
                basetype = ndr_full(data=basetype, name=basetype.name)
            
            if ref:
                if direction == "both":
                    pass
                    #basetype = ndr_ref(data=basetype, name=basetype.name)
                    
            # opcodes dont pack single pointers
            if single:
                pass
                #basetype = ndr_unique(data=basetype, name=basetype.name)
            
            if double:
                basetype = ndr_unique(data=basetype, name=basetype.name)
                
            if triple:
                basetype = ndr_unique(data=ndr_unique(data=basetype, name=basetype.name), name=basetype.name)
                
            # Do this until we know whats gonna happen
            ndr_type = basetype
            
            elements.append(ndr_type)
            
            token = scanner.read()
            
            # Reset State
            direction = None
    
            unique = False
            ptr    = False
            ref    = False
            single = False
            double = False
            triple = False
    
            string = False
            context_handle = False
            
            array_type = None
            
            range = None
            fixed_num = None
            size_is = None
            length_is = None
            first_is = None
            last_is = None
            max_is = None
            
            switch_is = None
            
            basetype = None
            name = None
            
            ndr_type = None
            
        elif token[0] == "opcode_element_out":
            # Skip out element parsing
            
            direction = "out"
            
            while True:
                token = scanner.read()
                
                if token[0] == "opcode_element_context_handle":
                    context_handle = True
                    
                if token[0] == "opcode_element_end":
                    break
                elif token[0] == "opcode_end":
                    break
        else:
            # Element parsing
            #print "[*] Element [%s]" % token[0]
            #raw_input()
            
            # Lets do direction
            if token[0] == "opcode_element_in":
                direction = "in"
            elif token[0] == "opcode_element_in_out":
                direction = "both"
            
            # Lets do pointers
            elif token[0] == "opcode_element_unique":
                unique = True
            elif token[0] == "opcode_element_ptr":
                ptr = True
            elif token[0] == "opcode_element_ref":
                ref = True
            elif token[0] == "opcode_element_single_unique":
                single = True
            elif token[0] == "opcode_element_double_unique":
                double = True
            elif token[0] == "opcode_element_triple_unique":
                triple = True
            elif token[0] == "opcode_element_string":
                string = True
            
            # Lets do random decs
            elif token[0] == "opcode_element_context_handle":
                context_handle = True
                
            # Lets get fixed array
            elif token[0] == "opcode_element_array_fixed":
                print token[1]
                fixed_num = int(re.compile('(\d*)').split(token[1])[1])
                print fixed_num
                
            # Lets figure out dynamic shit
            elif token[0] == "opcode_element_range":
                range = token[1]
            elif token[0] == "opcode_element_array_size_is":
                size_is = token[1]
            elif token[0] == "opcode_element_array_length_is":
                length_is = token[1]
            elif token[0] == "opcode_element_array_first_is":
                first_is = token[1]
            elif token[0] == "opcode_element_array_last_is":
                last_is = token[1]
            elif token[0] == "opcode_element_array_max_is":
                max_is = token[1]
                
            # Lets do basic data types
            elif token[0] == "opcode_element_void":
                basetype = ndr_void()
            elif token[0] == "opcode_element_hyper":
                basetype = ndr_hyper()
            elif token[0] == "opcode_element_long":
                basetype = ndr_long()
            elif token[0] == "opcode_element_short":
                basetype = ndr_short()
            elif token[0] == "opcode_element_small":
                basetype = ndr_small()
            elif token[0] == "opcode_element_byte":
                basetype = ndr_byte()
            elif token[0] == "opcode_element_char":
                basetype = ndr_char()
            elif token[0] == "opcode_element_float":
                basetype = ndr_float()
            elif token[0] == "opcode_element_double":
                basetype = ndr_double()
            elif token[0] == "opcode_element_wchar_t":
                basetype = ndr_wchar()
        
            # Find switch_is for potential union
            elif token[0] == "opcode_element_switch_is":
                switch_is = re.compile('.*\((.*)\)').split(token[1])[1]
                
                for elem in elements:
                    if elem.name == switch_is:
                        switch_is = elem
                
                if isinstance(switch_is, str):
                    abort("[!] Switch_is not an ndr object, [%s]" % switch_is)
                    
            # Lets rock structures and unions
            elif token[0] == "opcode_element_struct_name":
                name = token[1]
                
                # Get our structure from the defined list
                if global_info.defined.has_key(name):
                    basetype = copy.deepcopy(global_info.defined[name])
                    basetype.defname = global_info.defined[name].name       
                else:
                    abort("Unknown structure [%s]" % name)
                            
            elif token[0] == "opcode_element_union_name":
                name = token[1] 
                
                # Get our union from the defined list
                if global_info.defined.has_key(name):
                    basetype = copy.deepcopy(global_info.defined[name])
                    basetype.defname = global_info.defined[name].name
                    basetype.switch_dep = switch_is
                else:
                    abort("Unknown union [%s]" % name)
            
            # Enums
            elif token[0] == "opcode_element_enum16":
                basetype = ndr_enum16()
                                
            # Some rare objects
            elif token[0] == "opcode_element_pipe":
                basetype = ndr_pipe()
            elif token[0] == "opcode_element_handle_t":
                basetype = ndr_handle_t()
            elif token[0] == "opcode_element_error_status_t":
                basetype = ndr_error_status()
            elif token[0] == "opcode_element_interface":
                interface_name = re.compile('.*\((.*)\)').split(token[1])[1]
                
                basetype = ndr_interface(data=interface_name)
            
            # Unknown
            elif token[0] == "generic_UNKNOWN":
                basetype = ndr_long()
                
            # Lets get names
            elif token[0] == "opcode_element_argument_name":
                name = token[1]
                
            token = scanner.read()

    # Loop through arrays fill in counts
    depelements = elements
    for element in elements:
        # unique is obscuring our check
        while isinstance(element, ndr_unique):
            element = element.data
            
        if isinstance(element, ndr_array_conformant):
            for dep in depelements:
                if dep.name == element.count:
                    element.count = dep
        elif isinstance(element, ndr_array_varying):
            for dep in depelements:
                if dep.name == element.count:
                    element.count = dep
        elif isinstance(element, ndr_array_conformant_varying):
            for dep in depelements:
                if dep.name == element.maxcount:
                    element.maxcount = dep
                    
                if dep.name == element.passed:
                    element.passed = dep
                        
    if DEBUG:
        print "------------------------"
        print "[*] Finished opcode %s\n" % opnum

    opcode_instance = ndr_opcode(opnum=int(opnum, 16), address=address, elements=elements, out=opcode_out)

    return opcode_instance

##############################################################################################
def parse_structure(token, struct_name, scanner, global_info):
    '''
    Parses an IDL structure
    '''

    elements = []
    names = []

    unique = False
    ptr    = False
    ref    = False
    single = False
    double = False
    triple = False
    
    string = False
    
    struct_type = None
    array_type = None
    
    enum = None
    range = None
    fixed_num = None
    array_empty = None
    size_is = None
    length_is = None
    first_is = None
    last_is = None
    max_is = None
    
    basetype = None
    
    structname = None
    switch_is = None
    unionname = None
    
    name = None
    
    ndr_type = None
    
    # Im in opcode state
    while True:
        if token[0] == "structure_end":
            #print "[*] Ending structure block"
            
            break
        elif token[0] == "structure_element_end":
            #print "[*] Ending structure element"
            
            if string:
                if fixed_num and isinstance(basetype, ndr_wchar):
                    basetype = ndr_wstring_nonconformant(size=fixed_num)
                elif fixed_num and isinstance(basetype, ndr_char):
                    basetype = ndr_string_nonconformant(size=fixed_num)
                elif isinstance(basetype, ndr_wchar):
                    basetype = ndr_wstring()
                elif isinstance(basetype, ndr_char):
                    basetype = ndr_string()
     
            if size_is or length_is or first_is or last_is or max_is or fixed_num and not string:
                basetype = get_array(basetype, size_is, max_is, length_is, first_is, last_is, fixed_num)

                if isinstance(basetype, ndr_array_conformant) and array_empty:
                    struct_type = "conformant"
                else:
                    struct_type = "complex"
            
            if isinstance(basetype, ndr_short) and enum:
                basetype = ndr_enum16()
                                    
            if isinstance(basetype, ndr_union):
                for elem in elements:
                    if elem.name == switch_is:
                        basetype.switch_dep = elem
                
                # This is temporary until we figure something out
                if switch_is.startswith("callback"):
                    basetype.switch_dep = ndr_callback(data=0x4)
                    
                if isinstance(basetype.switch_dep, str):
                    abort("[!] Switch_is not an ndr object, [%s]" % basetype.switch_dep)
                    
            if not basetype:
                abort("[!] Got None basetype")
                            
            basetype.name = name
            
            if unique:
                basetype = ndr_unique(data=basetype, name=basetype.name)
            
            if ptr:
                basetype = ndr_full(data=basetype, name=basetype.name)
                
            if single:
                basetype = ndr_unique(data=basetype, name=basetype.name)
            
            if double:
                basetype = ndr_unique(data=basetype, name=basetype.name)
                
            if triple:
                basetype = ndr_unique(data=basetype, name=basetype.name)
                
            # Do this until we know whats gonna happen
            ndr_type = basetype
            
            type = deref_ndr(ndr_type)
            if isinstance(type, ndr_struct) or isinstance(type, ndr_struct):
                if not type.defname:
                    abort("[!] Empty struct elem defname")
                    
            # Add our ndr element to the structure elements
            elements.append(ndr_type)
            
            token = scanner.read()
            
            # Reset State

            unique = False
            ptr    = False
            ref    = False
            single = False
            double = False
            triple = False
            
            string = False
            
            array_type = None
            
            enum = None
            range = None
            fixed_num = None
            array_empty = None
            size_is = None
            length_is = None
            first_is = None
            last_is = None
            max_is = None
            
            basetype = None
            
            structname = None
            switch_is = None
            unionname = None
            
            name = None
            
            ndr_type = None

        else:
            # Element parsing
            #print "[*] Element [%s]" % token[0]
            

            # Lets do pointers (Test the unique shit)
            if token[0] == "structure_element_unique":
                unique = True
            elif token[0] == "structure_element_ptr":
                ptr = True
            elif token[0] == "structure_element_ref":
                ref = True
            elif token[0] == "structure_element_single_unique":
                single = True
            elif token[0] == "structure_element_double_unique":
                double = True
            elif token[0] == "structure_element_triple_unique":
                triple = True
            elif token[0] == "structure_element_string":
                string = True
            
            # Lets do random decs
            elif token[0] == "structure_element_context_handle":
                basetype = ndr_context_handle()
                
            # Lets get fixed array
            elif token[0] == "structure_element_array_fixed":
                fixed_num = int(re.compile('(\d*)').split(token[1])[1])
            elif token[0] == "structure_element_array_empty":
                array_empty = True
                    
            # Lets figure out dynamic shit
            elif token[0] == "structure_element_range":
                range = token[1]
            elif token[0] == "structure_element_array_size_is":
                size_is = token[1]
            elif token[0] == "structure_element_array_length_is":
                length_is = token[1]
            elif token[0] == "structure_element_array_first_is":
                first_is = token[1]
            elif token[0] == "structure_element_array_last_is":
                last_is = token[1]
            elif token[0] == "structure_element_array_max_is":
                max_is = token[1]
            
            # Lets do basic data types
            elif token[0] == "structure_element_void":
                basetype = ndr_void()
            elif token[0] == "structure_element_hyper":
                basetype = ndr_hyper()
            elif token[0] == "structure_element_long":
                basetype = ndr_long()
            elif token[0] == "structure_element_short":
                basetype = ndr_short()
            elif token[0] == "structure_element_small":
                basetype = ndr_small()
            elif token[0] == "structure_element_byte":
                basetype = ndr_byte()
            elif token[0] == "structure_element_char":
                basetype = ndr_char()
            elif token[0] == "structure_element_float":
                basetype = ndr_float()
            elif token[0] == "structure_element_double":
                basetype = ndr_double()
            elif token[0] == "structure_element_wchar_t":
                basetype = ndr_wchar()
        
            # Find switch_is for potential union
            elif token[0] == "structure_element_switch_is":
                switch_is = re.compile('.*\((.*)\)').split(token[1])[1]
                
            # Lets rock structures and unions
            elif token[0] == "structure_element_struct_name":
                structname = token[1]
                
                basetype = ndr_struct(defname=structname)
            elif token[0] == "structure_element_union_name":
                unionname = token[1]
                
                basetype = ndr_union(defname=unionname)
            
            # Enums
            elif token[0] == "structure_element_enum16":
                enum = True
                    
            # Some rare objects
            elif token[0] == "structure_element_pipe":
                basetype = ndr_pipe()
            elif token[0] == "structure_element_handle_t":
                basetype = ndr_handle_t()
            elif token[0] == "structure_element_error_status_t":
                basetype = ndr_error_status()
            elif token[0] == "structure_element_interface":
                interface_name = re.compile('.*\((.*)\)').split(token[1])[1]
                
                basetype = ndr_interface(data=interface_name)
            
            # Unknown
            elif token[0] == "generic_UNKNOWN":
                basetype = ndr_long()
                
            # Lets get names
            elif token[0] == "structure_element_name":
                name = token[1]
            
            token = scanner.read()
    # Done parsing
    
    # Loop through arrays fill in counts
    depelements = elements
    for element in elements:
        # unique is obscuring our check
        while isinstance(element, ndr_unique):
            element = element.data
            
        if isinstance(element, ndr_array_conformant):
            for dep in depelements:
                if dep.name == element.count:
                    element.count = dep
        elif isinstance(element, ndr_array_varying):
            for dep in depelements:
                if dep.name == element.count:
                    element.count = dep
        elif isinstance(element, ndr_array_conformant_varying):
            for dep in depelements:
                if dep.name == element.maxcount:
                    element.maxcount = dep
                    
                if dep.name == element.passed:
                    element.passed = dep
                           
    # Create the new structure
    new_struct = ndr_struct(elements=elements, name=struct_name, type=struct_type)

    for elem_index in xrange(0, len(elements)):
        elem = deref_ndr(elements[elem_index])
        
        # See if we know about this union/structure    
        if isinstance(elem, ndr_struct) or isinstance(elem, ndr_union):
            # If we dont have a key it must be undefined
            if elem.defname not in global_info.defined:
                # Add it to the undefined
                if DEBUG:
                    print "[!] Adding [%s] to undefined because of [%s] -> [%s]" % (new_struct.name, elem.name, elem.defname)
                    
                global_info.undefined[new_struct.name] = new_struct
                
                return
            else:
                # We deep copy all objects into this instance so it can be
                # individually manipulated
                if isinstance(elements[elem_index], ndr_unique):
                    if isinstance(elements[elem_index].data, ndr_array_conformant) or isinstance(elements[elem_index].data, ndr_array_varying) or isinstance(elements[elem_index].data, ndr_array_conformant_varying) or isinstance(elements[elem_index].data, ndr_array_fixed):
                        name = elements[elem_index].data.basetype.name
                        defname = elements[elem_index].data.basetype.defname
                        
                        elements[elem_index].data.basetype = copy.deepcopy(global_info.defined[elem.defname])
                        
                        elements[elem_index].data.basetype.name = name
                        elements[elem_index].data.basetype.defname = defname
                    else:
                        name = elements[elem_index].data.name
                        defname = elements[elem_index].data.defname
                        
                        elements[elem_index].data = copy.deepcopy(global_info.defined[elem.defname])
                        
                        elements[elem_index].data.name = name
                        elements[elem_index].data.defname = defname
                elif isinstance(elements[elem_index], ndr_array_conformant) or isinstance(elements[elem_index], ndr_array_varying) or isinstance(elements[elem_index], ndr_array_conformant_varying) or isinstance(elements[elem_index], ndr_array_fixed):
                    name = elements[elem_index].basetype.name
                    defname = elements[elem_index].basetype.defname
                    
                    elements[elem_index].basetype = copy.deepcopy(global_info.defined[elem.defname])
                    
                    elements[elem_index].basetype.name = name
                    elements[elem_index].basetype.defname = defname
                else:
                    name = elements[elem_index].name
                    defname = elements[elem_index].defname
                    
                    elements[elem_index] = copy.deepcopy(global_info.defined[elem.defname])
                    
                    elements[elem_index].name = name
                    elements[elem_index].defname = defname
                
                
    # If we are here then all union/structs are known
    if DEBUG:
        print "[!] Adding [%s] to defined" % (new_struct.name)
        
    global_info.defined[new_struct.name] = new_struct
    
    return

##############################################################################################
def parse_union(token, union_name, switch_type, scanner, global_info):
    '''
    Parses an IDL union
    '''

    elements = []
    names = []
    
    default = False
    
    case = None
    
    unique = False
    ptr    = False
    ref    = False
    single = False
    double = False
    triple = False
    
    string = False
    
    array_type = None
    
    range = None
    fixed_num = None
    size_is = None
    length_is = None
    first_is = None
    last_is = None
    max_is = None
    
    switch_is = None
    basetype = None
    name = None
    
    ndr_type = None
    
    unsigned = False
    enum = None
    switch_basetype = None
    
    # We pull out our switch type object
    for switch_token in switch_type:
        if switch_token[0] == "union_element_unsigned":
            unsigned = True
        elif switch_token[0] == "union_element_long":
            switch_basetype = ndr_long()
        elif switch_token[0] == "union_element_enum16":
            enum = ndr_enum16()
        elif switch_token[0] == "union_element_short":
            switch_basetype = ndr_short()
        elif switch_token[0] == "union_element_small":
            switch_basetype = ndr_small()
    
    if unsigned and isinstance(switch_basetype, ndr_long):
        switch_basetype.signed = False
    
    # Im in union state
    while True:
        if token[0] == "union_end":
            if DEBUG:
                print "[*] Ending union block"
            
            break
        elif token[0] == "union_element_end":
            if DEBUG:
                print "[*] Ending union element"

            # Handle default case
            if default:
                case = -1
                basetype = ndr_empty()
                
            if size_is or length_is or first_is or last_is or max_is or fixed_num:
                basetype = get_array(basetype, size_is, max_is, length_is, first_is, last_is, fixed_num)
    
            if string:
                if isinstance(basetype, ndr_wchar):
                    basetype = ndr_wstring()
                elif isinstance(basetype, ndr_char):
                    basetype = ndr_string()
            
            if isinstance(basetype, ndr_union):
                for elem in elements:
                    if elem.name == switch_is:
                        basetype.switch_dep = elem
                        
                if isinstance(basetype.switch_dep, str):                                       
                    abort("[!] Switch_is not an ndr object, [%s]" % basetype.switch_dep)                                       
                    
            if not basetype:
                if DEBUG: print "[!] Got None basetype, could be empty union element"
                basetype = ndr_empty()
                
            basetype.name = name
            
            if unique:
                basetype = ndr_unique(data=basetype, name=basetype.name)
            
            if single:
                basetype = ndr_unique(data=basetype, name=basetype.name)
            
            if double:
                basetype = ndr_unique(data=basetype, name=basetype.name)
                
            if triple:
                basetype = ndr_unique(data=basetype, name=basetype.name)
                
            # Do this until we know whats gonna happen
            ndr_type = basetype
            
            # Add our ndr element to the structure elements
            type = deref_ndr(ndr_type)
            if isinstance(type, ndr_struct) or isinstance(type, ndr_struct):
                if not type.name or not type.defname:
                    abort("[!] Empty struct elem defname")
            
            #print case, ndr_type
            elements.append((case, ndr_type))
            
            token = scanner.read()
            
            # Reset State
            default = False
            
            case = None
            
            unique = False
            ptr    = False
            ref    = False
            single = False
            double = False
            triple = False
            string = False
            
            array_type = None
            
            range = None
            fixed_num = None
            size_is = None
            length_is = None
            first_is = None
            last_is = None
            max_is = None
            
            switch_is = None
            basetype = None
            name = None
            
            ndr_type = None

        else:
            # Element parsing
            #print "[*] Element [%s]" % token[0]
            
            # Do switch_type handling
            if token[0] == "union_typedef":
                switch_type = []
                while True:
                    if token[0] == "union_declaration":
                        break
                    else:
                        switch_type.append(token)
                    
                    token = scanner.read()
                    
            # Handle default
            elif token[0] == "union_default":
                default = True
                
                name = "default"
            
            # Case
            elif token[0] == "union_case":
                # We int this string cause its a key in the dict
                case = int(re.compile('.*\((.*)\)').split(token[1])[1])
                
            # Lets do pointers
            elif token[0] == "union_element_unique":
                unique = True
            elif token[0] == "union_element_ptr":
                ptr = True
            elif token[0] == "union_element_ref":
                ref = True
            elif token[0] == "union_element_single_unique":
                single = True
            elif token[0] == "union_element_double_unique":
                double = True
            elif token[0] == "union_element_triple_unique":
                triple = True
            elif token[0] == "union_element_string":
                string = True
            
            # Lets do random decs
            elif token[0] == "union_element_context_handle":
                basetype = ndr_context_handle()
                
            # Lets get fixed array
            elif token[0] == "union_element_array_fixed":
                fixed_num = int(re.compile('(\d*)').split(token[1])[1])
                
            # Lets figure out dynamic shit
            elif token[0] == "union_element_range":
                range = token[1]
            elif token[0] == "union_element_array_size_is":
                size_is = token[1]
            elif token[0] == "union_element_array_length_is":
                length_is = token[1]
            elif token[0] == "union_element_array_first_is":
                first_is = token[1]
            elif token[0] == "union_element_array_last_is":
                last_is = token[1]
            elif token[0] == "union_element_array_max_is":
                max_is = token[1]
                
            # Lets figure out arrays
            
            # Lets do basic data types
            elif token[0] == "union_element_void":
                basetype = ndr_void()
            elif token[0] == "union_element_hyper":
                basetype = ndr_hyper()
            elif token[0] == "union_element_long":
                basetype = ndr_long()
            elif token[0] == "union_element_short":
                basetype = ndr_short()
            elif token[0] == "union_element_small":
                basetype = ndr_small()
            elif token[0] == "union_element_byte":
                basetype = ndr_byte()
            elif token[0] == "union_element_char":
                basetype = ndr_char()
            elif token[0] == "union_element_float":
                basetype = ndr_float()
            elif token[0] == "union_element_double":
                basetype = ndr_double()
            elif token[0] == "union_element_wchar_t":
                basetype = ndr_wchar()
        
            # Find switch_is for potential union
            elif token[0] == "union_element_switch_is":
                switch_is = re.compile('.*\((.*)\)').split(token[1])[1]
                    
            # Lets rock structures and unions
            elif token[0] == "union_element_struct_name":
                structname = token[1]
                
                basetype = ndr_struct(defname=structname)
            elif token[0] == "union_element_union_name":
                unionname = token[1]
                
                basetype = ndr_union(defname=unionname)
                
            # Some rare objects
            elif token[0] == "union_element_pipe":
                basetype = ndr_pipe()
            elif token[0] == "union_element_handle_t":
                basetype = ndr_handle_t()
            elif token[0] == "union_element_error_status_t":
                basetype = ndr_error_status()
            elif token[0] == "union_element_interface":
                interface_name = re.compile('.*\((.*)\)').split(token[1])[1]
                
                basetype = ndr_interface(data=interface_name)
            
            # Unknown
            elif token[0] == "generic_UNKNOWN":
                basetype = ndr_long()
                                
            # Lets get names
            elif token[0] == "union_element_name":
                name = token[1]
            
            token = scanner.read()
    
    # Loop through arrays fill in counts
    depelements = elements
    for element in elements:
        # unique is obscuring our check
        while isinstance(element, ndr_unique):
            element = element.data
            
        if isinstance(element, ndr_array_conformant):
            for dep in depelements:
                if dep.name == element.count:
                    element.count = dep
        elif isinstance(element, ndr_array_varying):
            for dep in depelements:
                if dep.name == element.count:
                    element.count = dep
        elif isinstance(element, ndr_array_conformant_varying):
            for dep in depelements:
                if dep.name == element.maxcount:
                    element.maxcount = dep
                    
                if dep.name == element.passed:
                    element.passed = dep
                     
    # Create the new union elements
    newelements = {}
    for (num, elem) in elements:
        newelements[num] = elem
        
    new_union = ndr_union(elements=newelements, switch_dep=switch_basetype, name=union_name)
    
    for case, elem in newelements.items():
        # Deref needed ndr types
        elem = deref_ndr(elem)
        
        # See if we know about this union/structure    
        if isinstance(elem, ndr_struct) or isinstance(elem, ndr_union):
            # If we dont have a key it must be undefined
            if elem.defname not in global_info.defined:
                # Add it to the undefined
                if DEBUG:
                    print "[!] Adding [%s] to undefined because of [%s] -> [%s]" % (new_union.name, elem.name, elem.defname)
                
                global_info.undefined[new_union.name] = new_union
                
                return
            else:
                if isinstance(newelements[case], ndr_unique):
                    if isinstance(newelements[case].data, ndr_array_conformant) or isinstance(newelements[case].data, ndr_array_varying) or isinstance(newelements[case].data, ndr_array_conformant_varying) or isinstance(newelements[case].data, ndr_array_fixed):
                        name = newelements[case].data.basetype.name
                        defname = newelements[case].data.basetype.defname
                        
                        newelements[case].data.basetype = copy.deepcopy(global_info.defined[elem.defname])
                        
                        newelements[case].data.basetype.name = name
                        newelements[case].data.basetype.defname = defname
                    else:
                        name = newelements[case].data.name
                        defname = newelements[case].data.defname
                        
                        newelements[case].data = copy.deepcopy(global_info.defined[elem.defname])
                        
                        newelements[case].data.name = name
                        newelements[case].data.defname = defname
                        
                elif isinstance(newelements[case], ndr_array_conformant) or isinstance(newelements[case], ndr_array_varying) or isinstance(newelements[case], ndr_array_conformant_varying) or isinstance(newelements[case], ndr_array_fixed):
                    name = newelements[case].basetype.name
                    defname = newelements[case].basetype.defname
                    
                    newelements[case].basetype = copy.deepcopy(global_info.defined[elem.defname])
                    
                    newelements[case].basetype.name = name
                    newelements[case].basetype.defname = defname
                else:
                    name = newelements[case].name
                    defname = newelements[case].defname
                    
                    newelements[case] = copy.deepcopy(global_info.defined[elem.defname])
                    
                    newelements[case].name = name
                    newelements[case].defname = defname
                          
    # If we are here then all union/structs are known
    if DEBUG:
        print "[!] Adding [%s] to defined" % (new_union.name)
    
    global_info.defined[new_union.name] = new_union
    
    return

##############################################################################################
def parse_idl(filename):

    if not filename:
        abort("Please supply a filename")
        raise
        
    if DEBUG: print "[*] Lexing %s...\n" % filename
    
    # retrieve lexicon from lexer
    try:
        lexicon = lexer.lexify()
    except:
        abort("Problem lexing %s, raising error..." % filename)
        raise


    # open IDL
    fh = open(filename, "r")

    # determine the number of UUIDs that are defined in this IDL
    raw = fh.read()
    uuid_count = raw.count("uuid(")
    current_uuid = 1
    fh.close()

    # need to close and re-open because Scanner is stupid.
    fh = open(filename, "r")

    # initialize the scanner
    scanner = Scanner(lexicon, fh, filename)

    # setup uuid list
    uuid_list = []
    
    # go go gadget parser
    while 1:

        if current_uuid == (uuid_count+1):
            break

        token = scanner.read()

        ##########################################################################
        # seek to the UUID we want to parse
        ##########################################################################
        done = False
        for i in xrange(0, current_uuid):
            while 1:
                if token[0] == "uuid" and i == (current_uuid-1):
                    done = True
                    break
                elif token[0] == "uuid" and i != (current_uuid-1):
                    break
                else:
                    if token[0] == "opnum":
                        scanner.begin("opcode")
                        while not token[0] == "opcode_end":
                            token = scanner.read()
                        scanner.begin("")
                    else:
                        token = scanner.read()
            if done:
                break
            token = scanner.read()

        ##########################################################################
        # get UUID itself
        ##########################################################################
        uuid_name = token[1][5:len(token[1])-1]
        print "[*] Parsing UUID %s" % uuid_name
        
        # instantiate GLOBALS
        global_info = GLOBALS()
        
        global_info.defined = {}
        global_info.undefined = {}

        
        uuid_instance = idl_UUID(ifid=uuid_name)

        ##########################################################################
        # get UUID version
        ##########################################################################
        token = scanner.read()
        version = token[1][8:len(token[1])-1]
        print "[*] UUID version %s" % version
        uuid_instance.version = version



        ##########################################################################
        # Parse ALL structures
        ##########################################################################
        if DEBUG:
            print "[*] Parsing structures"
            
        struct_count = 1
        while not token[0] == "uuid_end":

            ##########################################################################
            # Parse single structure
            ##########################################################################
            if token[0] == "structure_typedef":
                scanner.begin("structure")

                # parse struct name
                struct_name = token[1].split(" ")[2]

                if DEBUG:
                    print "[*] Found structure %s" % struct_name

                token = scanner.read()

                # parse this structure
                parse_structure(token, struct_name, scanner, global_info)

                struct_count += 1

                # reset the scanner state
                scanner.begin("")

            elif token[0] == None:
                break
                abort("Structure parsing hit a None")

            else:
                ##########################################################################
                # SKIP ALL OPCODES, we'll parse them later.
                ##########################################################################
                if token[0] == "opnum":
                    scanner.begin("opcode")

                    while token[0] != "opcode_end":
                        token = scanner.read()
                        
                    scanner.begin("")

                ##########################################################################
                # handle everything else in the default state
                ##########################################################################
                else:
                    token = scanner.read()

        # because of structure 0-indexing
        if struct_count != 1:
            struct_count -= 1
        else:
            struct_count = 0

        print "[*] Done parsing 0x%02x STRUCTURES for UUID %s" % (struct_count, uuid_name)

        # reset the scanner to the UUID we are parsing
        # need to close and re-open because Scanner is stupid.
        fh.close()
        fh = open(filename, "r")

        # initialize the scanner
        scanner = Scanner(lexicon, fh, filename)

        token = scanner.read()

        ##########################################################################
        # seek to the UUID we want to parse
        ##########################################################################
        done = False
        for i in xrange(0, current_uuid):
            while 1:
                if token[0] == "uuid" and i == (current_uuid-1):
                    done = True
                    break
                elif token[0] == "uuid" and i != (current_uuid-1):
                    break
                else:
                    if token[0] == "opnum":
                        scanner.begin("opcode")
                        while not token[0] == "opcode_end":
                            token = scanner.read()
                        scanner.begin("")
                    else:
                        token = scanner.read()
            if done:
                break
            token = scanner.read()


        ##########################################################################
        # Parse ALL unions
        ##########################################################################
        if DEBUG:
            print "[*] Parsing unions"
            
        union_count = 1
        while not token[0] == "uuid_end":

            ##########################################################################
            # Parse single union
            ##########################################################################
            if token[0] == "union_typedef":
                scanner.begin("union")

                # parse union switch_type
                switch_type = []
                while True:
                    if token[0] == "union_declaration":
                        break
                    
                    switch_type.append(token)
                    token = scanner.read()                    
                
                # Get union name
                union_name = token[1].split(" ")[2]

                if DEBUG:
                    print "[*] Found union %s" % union_name

                token = scanner.read()
                
                # parse this union
                parse_union(token, union_name, switch_type, scanner, global_info)
                union_count += 1

                # reset the scanner state
                scanner.begin("")

            elif token[0] == None:
                break
                abort("Union parsing hit a None")

            else:
                ##########################################################################
                # SKIP ALL OPCODES, we'll parse them later.
                ##########################################################################
                if token[0] == "opnum":
                    scanner.begin("opcode")

                    while not token[0] == "opcode_end":
                        token = scanner.read()
                    scanner.begin("")

                ##########################################################################
                # handle everything else in the default state
                ##########################################################################
                else:
                    token = scanner.read()

        # because of union 0-indexing
        if union_count != 1:
            union_count -= 1
        else:
            union_count = 0
        print "[*] Done parsing 0x%02x UNIONS for UUID %s" % (union_count, uuid_name)



        ##########################################################################
        # Fill in placeholders
        ##########################################################################
        
        # Infinite loop count
        count = 0
        
        #dump_list(global_info.defined, debug=True)
        
        while True:
            if not global_info.undefined.keys():
                if DEBUG: print "[*] Finished"
                
                break
                
            for undefined_key in global_info.undefined.keys():
                found = True
                
                if DEBUG:
                    print "[*] Checking %s" % undefined_key
                
                # Make readable
                undefined = global_info.undefined[undefined_key]

                if isinstance(undefined, ndr_struct):
                    for element_index in xrange(0, len(undefined.elements)):
                        element = undefined.elements[element_index]
                        
                        # Deref arrays/uniques
                        element = deref_ndr(element)
                        
                        # Make sure its a struct/union
                        if isinstance(element, ndr_struct) or isinstance(element, ndr_union):
                            if not element.defname:
                                abort("[%s] [%s] no defname" % (undefined.name, element.name))
                            
                            if element.defname == undefined.name:
                                if DEBUG:
                                    print "[!] Breaking due to infinite loop"
                                    
                                break
                                 
                            if element.defname in global_info.defined:
                                if DEBUG:
                                    print "    [%s] [%s] [%s]" % (element.name, element.defname, element)
                                
                                # Copy the object into the struct (we need to mind the pointers
                                undefined.elements[element_index].set_data(copy.deepcopy(global_info.defined[element.defname].get_data()))
                            else:
                                found = False
                                
                                if DEBUG:
                                    print "xxx [%s] [%s] [%s]" % (element.name, element.defname, element)
                                
                                break
                        
                elif isinstance(undefined, ndr_union):
                    for case_key in undefined.elements.keys():
                        # Deref arrays/uniques
                        element = deref_ndr(undefined.elements[case_key])
                        
                        # Make sure its a struct/union
                        if isinstance(element, ndr_struct) or isinstance(element, ndr_union):
                            if not element.defname:
                                abort("[%s] [%s] no defname" % (undefined.name, element.name))
                                
                            if element.defname in global_info.defined:
                                if DEBUG:
                                    print "    [%s] [%s] [%s]" % (element.name, element.defname, element)
                                
                                undefined.elements[case_key].set_data(copy.deepcopy(global_info.defined[element.defname].get_data()))
                            else:
                                found = False
                                
                                if DEBUG:
                                    print "xxx [%s] [%s] [%s]" % (element.name, element.defname, element)
                                    
                                break
                    
                else:
                    abort("[!] Unknown undefined type [%s]" % global_info.undefined[undefined_key])
                
                if found:
                    global_info.defined[undefined_key] = global_info.undefined[undefined_key]
                    del global_info.undefined[undefined_key]
                    
                    count = 0
                else:
                    count += 1
                 
        # Debug dump of defined list (includes ndr tree)                
        #dump_list(global_info.defined, debug=True)
        #raw_input()
        
        # reset the scanner to the UUID we are parsing
        # need to close and re-open because Scanner is stupid.
        fh.close()
        fh = open(filename, "r")

        # initialize the scanner
        scanner = Scanner(lexicon, fh, filename)

        token = scanner.read()

        ##########################################################################
        # seek to the UUID we want to parse
        ##########################################################################
        done = False
        for i in xrange(0, current_uuid):
            while 1:
                if token[0] == "uuid" and i == (current_uuid-1):
                    done = True
                    break
                elif token[0] == "uuid" and i != (current_uuid-1):
                    break
                else:
                    if token[0] == "opnum":
                        scanner.begin("opcode")
                        while not token[0] == "opcode_end":
                            token = scanner.read()
                        scanner.begin("")
                    else:
                        token = scanner.read()
            if done:
                break
            token = scanner.read()

        ##########################################################################
        # Parse ALL opcodes
        ##########################################################################
        if DEBUG:
            print "[*] Parsing opcodes"
            
        opcode_count = 1
        opcode_list = []
        while not token[0] == "uuid_end":

            ##########################################################################
            # Parse single opcode
            ##########################################################################
            if token[0] == "opnum":
                scanner.begin("opcode")

                # parse opnum
                opnum = token[1][8:]
                token = scanner.read()

                # parse opcode address
                address = token[1][9:]

                while token[0] != "opcode_begin":
                    token = scanner.read()
                
                token = scanner.read()

                opcode_instance = parse_opcode(token, opnum, address, scanner, global_info)
                opcode_list.append(opcode_instance)
                opcode_count += 1

                # reset scanner state
                scanner.begin("")

            elif token[0] == None:
                break
                abort("Hit None while parsing opcodes")

            ##########################################################################
            # handle everything else in the default state
            ##########################################################################
            else:
                token = scanner.read()


        # because of opcode 0-indexing
        if opcode_count != 1:
            opcode_count -= 1
        else:
            opcode_count = 0

        print "[*] Done parsing 0x%02x OPCODES for UUID %s" % (opcode_count, uuid_name)

        # reset the scanner to the beginning
        # need to close and re-open because Scanner is stupid.
        fh.close()
        fh = open(filename, "r")

        # initialize the scanner
        scanner = Scanner(lexicon, fh, filename)

        # increment the UUID we are parsing
        current_uuid += 1

        # assign the defined objects to the UUID instance
        uuid_instance.objects = global_info.defined
        uuid_instance.opcodes = opcode_list
        uuid_list.append(uuid_instance)
        print "[*] Done parsing UUID %s\n" % uuid_name

    fh.close()

    return uuid_list

##############################################################################################
if __name__ == '__main__':
    parse_idl(sys.argv[1])
##############################################################################################
