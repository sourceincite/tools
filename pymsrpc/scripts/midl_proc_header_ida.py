#!/usr/bin/env python

'''
    midl_proc_header_ida.py
    
    This should make a comment if you have the cursor on the midl procedure header in IDA.
    
    (c) 2007 Cody Pierce - See LICENSE.txt
'''

# INTERPRETER_OPT_FLAGS2 <1>
HasNewCorrDesc     = 0x01
ClientCorrCheck    = 0x02
ServerCorrCheck    = 0x04
HasNotify          = 0x08
HasNotify2         = 0x10
Unused             = None
  
# PARAM_ATTRIBUTES <2>
MustSize           = 0x0001
MustFree           = 0x0002
IsPipe             = 0x0004
IsIn               = 0x0008
IsOut              = 0x0010
IsReturn           = 0x0020
IsBasetype         = 0x0040
IsByValue          = 0x0080
IsSimpleRef        = 0x0100
IsDontCallFreeInst = 0x0200
SaveForAsyncFinish = 0x0400
Unused             = None
ServerAllocSize    = 0xe000

def get_interpreter_opt_flags2(chary):
    chary &= 0x000000ff
    
    comment = "Ext Flags: "
    
    if (chary & HasNewCorrDesc): comment += "new corr desc, "
    if (chary & ClientCorrCheck): comment += "client corr check, "
    if (chary & ServerCorrCheck): comment += "server corr check, "
    if (chary & HasNotify): comment += "notify, "
    if (chary & HasNotify2): comment += "notify2, "
    #if (chary & Unused): comment += "Unused"
    
    return comment.rstrip().rstrip(',')
    
def get_param_attributes(shorty):
    shorty &= 0x0000ffff
    
    comment = "Flags: "
    
    if (shorty & MustSize): comment += "must size, "
    if (shorty & MustFree): comment += "must free, "
    if (shorty & IsPipe): comment += "pipe, "
    if (shorty & IsIn): comment += "[in], "
    if (shorty & IsOut): comment += "[out], "
    if (shorty & IsReturn): comment += "return, "
    if (shorty & IsBasetype): comment += "base type, "
    if (shorty & IsByValue): comment += "by value, "
    if (shorty & IsSimpleRef): comment += "simple ref, "
    if (shorty & IsDontCallFreeInst): comment += "dont call free inst, "
    if (shorty & SaveForAsyncFinish): comment += "save for async finish, "
    #if (shorty & Unused): comment += "Unused"
    if (shorty & ServerAllocSize): comment += "server alloc size"

    return comment.rstrip().rstrip(',')
    
current_ea = ScreenEA()
shorty = Word(current_ea)
comment = get_param_attributes(shorty)
#chary = Byte(current_ea)
#comment = get_interpreter_opt_flags2(chary)

if not MakeComm(current_ea, comment):
    print "[!] Problem creating comment @ %08x %s" % (current_ea, comment)