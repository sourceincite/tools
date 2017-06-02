#!/usr/bin/env python

'''
    midl_type_comment_ida.py
    
    This will create a comment of the underlying midl type at cursor in IDA
    
    (c) 2007 Cody Pierce - See LICENSE.txt
'''

import sys

midl_types = [
    "FC_ZERO", 0x00,
    "FC_BYTE", 0x01,
    "FC_CHAR", 0x02,
    "FC_SMALL", 0x03,
    "FC_USMALL", 0x04,
    "FC_WCHAR", 0x05,
    "FC_SHORT", 0x06,
    "FC_USHORT", 0x07,
    "FC_LONG", 0x08,
    "FC_ULONG", 0x09,
    "FC_FLOAT", 0x0a,
    "FC_HYPER", 0x0b,
    "FC_DOUBLE", 0x0c,
    "FC_ENUM16", 0x0d,
    "FC_ENUM32", 0x0e,
    "FC_IGNORE", 0x0f,
    "FC_ERROR_STATUS_T", 0x10,
    "FC_RP", 0x11,
    "FC_UP", 0x12,
    "FC_OP", 0x13,
    "FC_FP", 0x14,
    "FC_STRUCT", 0x15,
    "FC_PSTRUCT", 0x16,
    "FC_CSTRUCT", 0x17,
    "FC_CPSTRUCT", 0x18,
    "FC_CVSTRUCT", 0x19,
    "FC_BOGUS_STRUCT", 0x1a,
    "FC_CARRAY", 0x1b,
    "FC_CVARRAY", 0x1c,
    "FC_SMFARRAY", 0x1d,
    "FC_LGFARRAY", 0x1e,
    "FC_SMVARRAY", 0x1f,
    "FC_LGVARRAY", 0x20,
    "FC_BOGUS_ARRAY", 0x21,
    "FC_C_CSTRING", 0x22,
    "FC_C_BSTRING", 0x23,
    "FC_C_SSTRING", 0x24,
    "FC_C_WSTRING", 0x25,
    "FC_CSTRING", 0x26,
    "FC_BSTRING", 0x27,
    "FC_SSTRING", 0x28,
    "FC_WSTRING", 0x29,
    "FC_ENCAPSULATED_UNION", 0x2a,
    "FC_NON_ENCAPSULATED_UNION", 0x2b,
    "FC_BYTE_COUNT_POINTER", 0x2c,
    "FC_TRANSMIT_AS", 0x2d,
    "FC_REPRESENT_AS", 0x2e,
    "FC_IP", 0x2f,
    "FC_BIND_CONTEXT", 0x30,
    "FC_BIND_GENERIC", 0x31,
    "FC_BIND_PRIMITIVE", 0x32,
    "FC_AUTO_HANDLE", 0x33,
    "FC_CALLBACK_HANDLE", 0x34,
    "FC_UNUSED1", 0x35,
    "FC_POINTER", 0x36,
    "FC_ALIGNM2", 0x37,
    "FC_ALIGNM4", 0x38,
    "FC_ALIGNM8", 0x39,
    "FC_UNUSED2", 0x3a,
    "FC_UNUSED3", 0x3b,
    "FC_UNUSED4", 0x3c,
    "FC_STRUCTPAD1", 0x3d,
    "FC_STRUCTPAD2", 0x3e,
    "FC_STRUCTPAD3", 0x3f,
    "FC_STRUCTPAD4", 0x40,
    "FC_STRUCTPAD5", 0x41,
    "FC_STRUCTPAD6", 0x42,
    "FC_STRUCTPAD7", 0x43,
    "FC_STRING_SIZED", 0x44,
    "FC_UNUSED5", 0x45,
    "FC_NO_REPEAT", 0x46,
    "FC_FIXED_REPEAT", 0x47,
    "FC_VARIABLE_REPEAT", 0x48,
    "FC_FIXED_OFFSET", 0x49,
    "FC_VARIABLE_OFFSET", 0x4a,
    "FC_PP", 0x4b,
    "FC_EMBEDDED_COMPLEX", 0x4c,
    "FC_IN_PARAM", 0x4d,
    "FC_IN_PARAM_BASETYPE", 0x4e,
    "FC_IN_PARAM_NO_FREE_INST", 0x4d,
    "FC_IN_OUT_PARAM", 0x50,
    "FC_OUT_PARAM", 0x51,
    "FC_RETURN_PARAM", 0x52,
    "FC_RETURN_PARAM_BASETYPE", 0x53,
    "FC_DEREFERENCE", 0x54,
    "FC_DIV_2", 0x55,
    "FC_MULT_2", 0x56,
    "FC_ADD_1", 0x57,
    "FC_SUB_1", 0x58,
    "FC_CALLBACK", 0x59,
    "FC_CONSTANT_IID", 0x5a,
    "FC_END", 0x5b,
    "FC_PAD", 0x5c,
    "FC_SPLIT_DEREFERENCE", 0x74,
    "FC_SPLIT_DIV_2", 0x75,
    "FC_SPLIT_MULT_2", 0x76,
    "FC_SPLIT_ADD_1", 0x77,
    "FC_SPLIT_SUB_1", 0x78,
    "FC_SPLIT_CALLBACK", 0x79,
    "FC_HARD_STRUCT", 0xb1,
    "FC_TRANSMIT_AS_PTR", 0xb2,
    "FC_REPRESENT_AS_PTR", 0xb3,
    "FC_USER_MARSHAL", 0xb4,
    "FC_PIPE", 0xb5,
    "FC_BLKHOLE",  0xb6,
    "FC_RANGE",  0xb7,
    "FC_INT3264",  0xb8,
    "FC_UINT3264",  0xb9,
    "FC_END_OF_UNIVERSE",  0xba
]

def get_type(shorty):
    chary = shorty & 0x000000ff
    
    comment = midl_types[chary * 2]
    
    return comment
    
current_ea = ScreenEA()
shorty = Word(current_ea)
comment = get_type(shorty)

if not MakeComm(current_ea, comment):
    print "[!] Problem creating comment @ %08x %s" % (current_ea, comment)