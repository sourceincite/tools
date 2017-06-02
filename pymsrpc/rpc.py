
'''
rpc.py
    
A convenience wrapper to the fantastic impacket (Core Security) transport library.
    
(c) 2007 Cody Pierce - BSD License - See LICENSE.txt

Patched by Steven Seeley (updates to impacket and plex)
'''

import struct, sys

try:
    from impacket.dcerpc.v5 import transport, rpcrt
    from impacket import dcerpc
    from impacket import uuid
except:
    print "(!) install the latest impacket"
    print "(+) pip install impacket"
    sys.exit(-1)

'''
    RPCtcp class wrapping the impacket code that connects to a tcp endpoint.
'''

class RPCtcp:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        
        self.rpctransport = None
        self.dce = None
        
        self.ifid = None
        self.ifversion = None
        
    def connect(self):
        self.rpctransport = transport.TCPTransport(self.host, dstport=self.port)
        self.rpctransport.connect()
        
        #self.dce = dcerpc.DCERPC_v5(self.rpctransport)
        self.dce = transport.DCERPC_v5(self.rpctransport)
        return None
    
    def bind(self, ifid, ifversion):
        self.ifid = ifid
        self.ifversion = ifversion
        
        self.dce.bind(uuid.uuidtup_to_bin((self.ifid, self.ifversion)))
        
        return None
    
    def send(self, request):
        self.dce.send(request)
        
        return None
        
    def recv(self):
        return self.dce.recv()
        
    def call(self, opcode, request):
        self.dce.call(opcode, request)
        
        return None
    
    def rpcerror(self, rpcerrno):
        if rpcrt.rpc_status_codes.has_key(rpcerrno):
            return dcerpc.rpc_status_codes[rpcerrno]
        else:
            return False
        
        return False

'''
    RPCnp class wrapping the impacket code that connects to a named pipe endpoint.
'''     
class RPCnp:
    def __init__(self, host, port, pipe, username="", password=""):
        self.host = host
        self.port = port
        self.pipe = pipe
        
        self.username = username
        self.password = password
        
        self.rpctransport = None
        self.dce = None
        
        self.ifid = None
        self.ifversion = None
        
    def connect(self):
        self.rpctransport = transport.SMBTransport(self.host, dstport=self.port, filename=self.pipe, username=self.username, password=self.password)
        
        self.dce = dcerpc.DCERPC_v5(self.rpctransport)
        
        self.dce.connect()
        
        return None
    
    def bind(self, ifid, ifversion):
        self.ifid = ifid
        self.ifversion = ifversion
        
        self.dce.bind(uuid.uuidtup_to_bin((self.ifid, self.ifversion)))
        
        return None
    
    def send(self, request):
        self.dce.send(request)
        
        return None
    
    def recv(self):
        return self.dce.recv()
        
    def call(self, opcode, request):
        self.dce.call(opcode, request)
        
        return None
    
    def rpcerror(self, rpcerrno):
        if dcerpc.rpc_status_codes.has_key(rpcerrno):
            rpcerror = dcerpc.rpc_status_codes[rpcerrno]
            return rpcerror
        else:
            return False
        
        return False
