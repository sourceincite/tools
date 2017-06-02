#!/usr/bin/env python

'''
    parse_test_np.py
    
    This script is an example of how to use the pysrpc libarary.  It loads a file,
    parses the idl converting it into the proper wire representation, then sends it
    over the impacket connection via np.  This can also do multiple requests for
    anything that needs a context handle by selecting an opcode that has an [out] ch.
    
    (c) 2007 Cody Pierce - BSD License - See LICENSE.txt
'''

# Python imports
import random, sys

# Pymsrpc imports
sys.path.append("..")

from rpc import *
from ndr import *
from parse import parse_idl
from debug import print_hex, dump_ndr

def usage():
    print "%s <idl filename> [host] [pipe] [opnum]" % sys.argv[0]
    sys.exit(-1)

    
DEBUG = False

send = False
do_context = False

filename = sys.argv[1]
opnum = False

if len(sys.argv) > 2:
    host = sys.argv[2]
    port = 445
    pipe = sys.argv[3]

    if len(sys.argv) == 5:
        opnum = int(sys.argv[4])
    
    send = True

    
idl = parse_idl(filename)
rpc = None

if not idl:
    print "[!] idl parsing problem."
    sys.exit(-1)

# We loop through all the uuid's returned by the idl parser
for uuid in idl:
    print uuid.ifid

    # We make a tcp connection to the endpoint via Impacket
    if send:
        print "[*] Connecting ncacn_np to [%s:\\\\PIPE\\%s]" % (host, pipe)
        rpc = RPCnp(host, port, pipe, username="Administrator", password="gr0ver")
        rpc.connect()
        
        print "[*] Binding to [%s][%s]" % (uuid.ifid, uuid.version)
        rpc.bind(uuid.ifid, uuid.version)
    
    # Lets check any context_handles
    context_handle = None
    if do_context:
        # We loop through all the opcodes for each uuid the parser gave us
        for opcode in uuid.opcodes:
            if not isinstance(opcode.out, ndr_context_handle):
                continue
            
            print "Context  opcode: %x [%02d]" % (opcode.opnum, len(opcode.elements))
            
            testpack = ""    
            request = ""
            
            # Again I have to pass twice because of union dependencies
            for element in opcode.elements:
                testpack += element.serialize()
            
            # This is all you do to serialize the data for the wire    
            request += opcode.serialize()
                
            print ""
            
            if send:
                print "[*] Sending [%d]" % (opcode.opnum)
                print "[*] [%s]" % print_hex(request)
                
                rpc.call(opcode.opnum, request)
                
                try:
                    recvbuffer = rpc.recv()
                except:
                    print "[!] Socket closed skipping uuid"
                    rpc = None
                    continue
                
                if recvbuffer:
                    try:
                        rpcerror = rpc.rpcerror(struct.unpack("<L", recvbuffer[:4])[0])
                    except:
                        print "[!] Problem with unpack of [%s]" % (recvbuffer)
                        sys.exit(-1)
                        
                    if not rpcerror:
                        print "[*] Received [%s]" % print_hex(recvbuffer)
                        context_handle = recvbuffer[:20]
                        break
                    else:
                        print "[!] RPC Error [%s]" % (rpcerror)
                        if rpcerror == "rpc_x_bad_stub_data":
                            raw_input('bad stub> ')
    
    # We loop through all the opcodes for each uuid the parser gave us             
    for opcode in uuid.opcodes:
        # We make a np connection to the endpoint via Impacket
        if not rpc and send:
            print "[*] Connecting ncacn_np to [%s:\\\\PIPE\\%s]" % (host, pipe)
            rpc = RPCnp(host, port, pipe, username="Administrator", password="password")
            rpc.connect()
            
            print "[*] Binding to [%s][%s]" % (uuid.ifid, uuid.version)
            rpc.bind(uuid.ifid, uuid.version)
            
        if opnum:
            if opcode.opnum != opnum:
                continue
            
        print "  opcode: %x [%02d]" % (opcode.opnum, len(opcode.elements))
        
        testpack = ""    
        request = ""
        
        if context_handle:
            opcode.set_context_handle(context_handle)
        
        # Again I have to pass twice because of union dependencies
        for element in opcode.elements:
            if DEBUG:
                dump_ndr(element)
                
            testpack += element.serialize()
        
        # This is all you do to serialize the data for the wire    
        request += opcode.serialize()
        
        print "[*] Sending [%d]" % (opcode.opnum)
        print "[*] [%s]" % print_hex(request)
            
        if send:    
            rpc.call(opcode.opnum, request)
            
            try:
                recvbuffer = rpc.recv()
            except:
                print "[!] Socket closed skipping uuid"
                rpc = None
                continue
            
            if recvbuffer:
                try:
                    rpcerror = rpc.rpcerror(struct.unpack("<L", recvbuffer[:4])[0])
                except:
                    print "[!] Problem with unpack of [%s]" % (recvbuffer)
                    sys.exit(-1)
                    
                if not rpcerror:
                    print "[*] Received [%s]" % print_hex(recvbuffer)
                else:
                    print "[!] RPC Error [%s]" % (rpcerror)
                    if rpcerror == "rpc_x_bad_stub_data":
                        # AAAAAAAAAAAHHHHHHHHHHHHHHHHHHHHHHHHHH!
                        raw_input("bad stub> ")