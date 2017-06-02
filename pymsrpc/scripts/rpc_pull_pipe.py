#!/usr/bin/env python

import sys, os, time, re

'''
    rpc_pull_pipe.py
    
    This script is kind of dumb but it will output a template for accessing the binary you run
    this on in IDA.  I basically look for any xref to RpcServerUseProtseqEp and then walk back
    to find the pipe name that is being supplied to it.  This will fail in many cases but fuck it.
    
    (c) 2007 Cody Pierce - See LICENSE.txt
'''

####################################################
#
# Lib calls stuff
#
####################################################
def get_string(ea):
    str_type = GetStringType(ea)

    s = ""
    if str_type == 0:
        while Byte(ea) != 0x00:
            s += chr(Byte(ea))
            ea += 1
    elif str_type == 3:
        while Word(ea) != 0x0000:
            s += chr(Byte(ea))
            ea += 2

    return s
    
def get_arguments(ea):
    xref_ea = ea
    args = 0
    arglist = []
    
    if GetMnem(xref_ea) != "call":
        return False

    cur_ea = PrevHead(ea, xref_ea - 32)
    while (cur_ea < xref_ea - 32) or (args <= 6):
        cur_mnem = GetMnem(cur_ea);
        if cur_mnem == "push":
            op_type = GetOpType(cur_ea, 0)

            if op_type == 5:
                    arglist.append(get_string(GetOperandValue(cur_ea, 0)))
            
            args += 1
        elif cur_mnem == "call" or "j" in cur_mnem:
            break;

        cur_ea = PrevHead(cur_ea, xref_ea - 32)

    return arglist
    
def get_lib_calls(ea):
    seg_start = ea
    seg_end = SegEnd(seg_start)
    arglist = []
    seqs = []
    
    import_ea = seg_start

    while  import_ea < seg_end:
        import_name = Name(import_ea);
        if "RpcServerUseProtseqEp" in import_name:    
            xref_start = import_ea
            xref_cur = DfirstB(xref_start)
            while xref_cur != BADADDR:                
                arglist = get_arguments(xref_cur)
                
                if arglist and len(arglist) > 2:
                    seqs.append({"type": arglist[0], "name": arglist[2]})
                        
                xref_cur = DnextB(xref_start, xref_cur)

        import_ea += 4
    
    return seqs

####################################################
#
# RPC template stuff
#
####################################################
def build_header(fh):
    fh.write( "#!/usr/bin/env python\n" )
    fh.write( "\n" )
    fh.write( "import random, sys\n" )
    fh.write( "\n" )
    fh.write( "from rpc import *\n" )
    fh.write( "from ndr import *\n" )
    fh.write( "from parse import parse\n" )
    fh.write( "from debug import print_hex\n" )
    fh.write( "\n" )
    fh.write( "idlname = sys.argv[1]\n" )
    fh.write( "host = sys.argv[2]\n" )
    
def build_middle(fh):
    fh.write( "idl = parse(idlname)\n" )
    fh.write( "\n" )
    fh.write( "if not idl:\n" )
    fh.write( "    print \"[!] idl parsing problem.\"\n" )
    fh.write( "    sys.exit(-1)\n" )
    fh.write( "\n" )
    fh.write( "for uuid in idl:\n" )
    
def build_footer(fh):
    fh.write( "    rpc.connect()\n" )
    fh.write( "    \n" )
    fh.write( "    print \"[*] Binding to [%s][%s]\" % (uuid.ifid, uuid.version)\n" )
    fh.write( "    rpc.bind(uuid.ifid, uuid.version)\n" ) 
    fh.write( "    \n" )
    fh.write( "    for opcode in uuid.opcodes:\n" )
    fh.write( "        request = \"\"\n" )
    fh.write( "        \n" )
    fh.write( "        for element in opcode.elements:\n" )
    fh.write( "            request += element.get_packed()\n" )
    fh.write( "        \n" )
    fh.write( "        print \"[*] Sending [%d][%s]\" % (opcode.opnum, repr(request))\n" )
    fh.write( "        \n" )
    fh.write( "        rpc.call(opcode.opnum, request)\n" )
    fh.write( "        \n" )
    fh.write( "        recvbuffer = rpc.recv()\n" )
    fh.write( "        \n" )
    fh.write( "        rpcerror = rpc.rpcerror(struct.unpack(\"<L\", recvbuffer[:4])[0])\n" )
    fh.write( "        if not rpcerror:\n" )
    fh.write( "            print repr(recvbuffer)\n" )
    fh.write( "        else:\n" )
    fh.write( "            print \"%s\" % (rpcerror)\n" )
    fh.write( "        \n" )
    fh.write( "        raw_input()\n" )
    fh.write( "\n" )
    fh.write( "    rpc.close()\n" )
    
def build_template(fh, seqs):
    for seq in seqs:
        if seq["type"] == "ncacn_np":
            sys.stdout.write("Found [%s] pipe name [%s]\n" % (seq["type"], seq["name"]))
            
            build_header(fh)
            
            fh.write( "port = 445\n" )
            fh.write( "pipe = \'%s\'\n" % seq["name"].split("\\", 2)[-1] )
            fh.write( "\n" )
            
            build_middle(fh)
            
            fh.write( "    print \"[*] Connecting ncacn_np to [%s]\" % host\n" )
            fh.write( "    rpc = RPCnp(host, port, pipe, username=\"Administrator\", password=\"gr0ver\")\n" )

            build_footer(fh)
            
# Ask user for filename
outputfilename = AskStr(GetInputFile().split(".")[0] + ".py", "Enter file name to write output:")
fh = open(outputfilename, "w")

seqs = []

# Get imports
sys.stdout.write("Getting dll imports\n")
sys.stdout.write("=" * 72)
sys.stdout.write("\n")
seqs = get_lib_calls(SegByName(".idata"))

build_template(fh, seqs)

fh.close()