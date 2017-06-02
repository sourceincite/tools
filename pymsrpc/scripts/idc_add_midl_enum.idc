
#include <idc.idc>

// This script adds an enum in ida for all the midl format chars
// (c) 2007 - Cody Pierce

static main()
{
    auto enum_id;
    
    enum_id = AddEnum(1, "MIDL_FORMAT_CHARACTERS", 0x0);

    if (enum_id != -1)
    {
        Message("[*] Created enum %d as MIDL_FORMAT_CHARACTERS\n", enum_id);
    
        AddConstEx(enum_id, "FC_ZERO", 0x0, -1);
        AddConstEx(enum_id, "FC_BYTE", 0x1, -1);
        AddConstEx(enum_id, "FC_CHAR", 0x2, -1);
        AddConstEx(enum_id, "FC_SMALL", 0x3, -1);
        AddConstEx(enum_id, "FC_USMALL", 0x4, -1);
        AddConstEx(enum_id, "FC_WCHAR", 0x5, -1);
        AddConstEx(enum_id, "FC_SHORT", 0x6, -1);
        AddConstEx(enum_id, "FC_USHORT", 0x7, -1);
        AddConstEx(enum_id, "FC_LONG", 0x8, -1);
        AddConstEx(enum_id, "FC_ULONG", 0x9, -1);
        AddConstEx(enum_id, "FC_FLOAT", 0xa, -1);
        AddConstEx(enum_id, "FC_HYPER", 0xb, -1);
        AddConstEx(enum_id, "FC_DOUBLE", 0xc, -1);
        AddConstEx(enum_id, "FC_ENUM16", 0xd, -1);
        AddConstEx(enum_id, "FC_ENUM32", 0xe, -1);
        AddConstEx(enum_id, "FC_IGNORE", 0xf, -1);
        AddConstEx(enum_id, "FC_ERROR_STATUS_T", 0x10, -1);
        AddConstEx(enum_id, "FC_RP", 0x11, -1);
        AddConstEx(enum_id, "FC_UP", 0x12, -1);
        AddConstEx(enum_id, "FC_OP", 0x13, -1);
        AddConstEx(enum_id, "FC_FP", 0x14, -1);
        AddConstEx(enum_id, "FC_STRUCT", 0x15, -1);
        AddConstEx(enum_id, "FC_PSTRUCT", 0x16, -1);
        AddConstEx(enum_id, "FC_CSTRUCT", 0x17, -1);
        AddConstEx(enum_id, "FC_CPSTRUCT", 0x18, -1);
        AddConstEx(enum_id, "FC_CVSTRUCT", 0x19, -1);
        AddConstEx(enum_id, "FC_BOGUS_STRUCT", 0x1a, -1);
        AddConstEx(enum_id, "FC_CARRAY", 0x1b, -1);
        AddConstEx(enum_id, "FC_CVARRAY", 0x1c, -1);
        AddConstEx(enum_id, "FC_SMFARRAY", 0x1d, -1);
        AddConstEx(enum_id, "FC_LGFARRAY", 0x1e, -1);
        AddConstEx(enum_id, "FC_SMVARRAY", 0x1f, -1);
        AddConstEx(enum_id, "FC_LGVARRAY", 0x20, -1);
        AddConstEx(enum_id, "FC_BOGUS_ARRAY", 0x21, -1);
        AddConstEx(enum_id, "FC_C_CSTRING", 0x22, -1);
        AddConstEx(enum_id, "FC_C_BSTRING", 0x23, -1);
        AddConstEx(enum_id, "FC_C_SSTRING", 0x24, -1);
        AddConstEx(enum_id, "FC_C_WSTRING", 0x25, -1);
        AddConstEx(enum_id, "FC_CSTRING", 0x26, -1);
        AddConstEx(enum_id, "FC_BSTRING", 0x27, -1);
        AddConstEx(enum_id, "FC_SSTRING", 0x28, -1);
        AddConstEx(enum_id, "FC_WSTRING", 0x29, -1);
        AddConstEx(enum_id, "FC_ENCAPSULATED_UNION", 0x2a, -1);
        AddConstEx(enum_id, "FC_NON_ENCAPSULATED_UNION", 0x2b, -1);
        AddConstEx(enum_id, "FC_BYTE_COUNT_POINTER", 0x2c, -1);
        AddConstEx(enum_id, "FC_TRANSMIT_AS", 0x2d, -1);
        AddConstEx(enum_id, "FC_REPRESENT_AS", 0x2e, -1);
        AddConstEx(enum_id, "FC_IP", 0x2f, -1);
        AddConstEx(enum_id, "FC_BIND_CONTEXT", 0x30, -1);
        AddConstEx(enum_id, "FC_BIND_GENERIC", 0x31, -1);
        AddConstEx(enum_id, "FC_BIND_PRIMITIVE", 0x32, -1);
        AddConstEx(enum_id, "FC_AUTO_HANDLE", 0x33, -1);
        AddConstEx(enum_id, "FC_CALLBACK_HANDLE", 0x34, -1);
        AddConstEx(enum_id, "FC_UNUSED1", 0x35, -1);
        AddConstEx(enum_id, "FC_POINTER", 0x36, -1);
        AddConstEx(enum_id, "FC_ALIGNM2", 0x37, -1);
        AddConstEx(enum_id, "FC_ALIGNM4", 0x38, -1);
        AddConstEx(enum_id, "FC_ALIGNM8", 0x39, -1);
        AddConstEx(enum_id, "FC_UNUSED2", 0x3a, -1);
        AddConstEx(enum_id, "FC_UNUSED3", 0x3b, -1);
        AddConstEx(enum_id, "FC_UNUSED4", 0x3c, -1);
        AddConstEx(enum_id, "FC_STRUCTPAD1", 0x3d, -1);
        AddConstEx(enum_id, "FC_STRUCTPAD2", 0x3e, -1);
        AddConstEx(enum_id, "FC_STRUCTPAD3", 0x3f, -1);
        AddConstEx(enum_id, "FC_STRUCTPAD4", 0x40, -1);
        AddConstEx(enum_id, "FC_STRUCTPAD5", 0x41, -1);
        AddConstEx(enum_id, "FC_STRUCTPAD6", 0x42, -1);
        AddConstEx(enum_id, "FC_STRUCTPAD7", 0x43, -1);
        AddConstEx(enum_id, "FC_STRING_SIZED", 0x44, -1);
        AddConstEx(enum_id, "FC_UNUSED5", 0x45, -1);
        AddConstEx(enum_id, "FC_NO_REPEAT", 0x46, -1);
        AddConstEx(enum_id, "FC_FIXED_REPEAT", 0x47, -1);
        AddConstEx(enum_id, "FC_VARIABLE_REPEAT", 0x48, -1);
        AddConstEx(enum_id, "FC_FIXED_OFFSET", 0x49, -1);
        AddConstEx(enum_id, "FC_VARIABLE_OFFSET", 0x4a, -1);
        AddConstEx(enum_id, "FC_PP", 0x4b, -1);
        AddConstEx(enum_id, "FC_EMBEDDED_COMPLEX", 0x4c, -1);
        AddConstEx(enum_id, "FC_IN_PARAM", 0x4d, -1);
        AddConstEx(enum_id, "FC_IN_PARAM_BASETYPE", 0x4e, -1);
        AddConstEx(enum_id, "FC_IN_PARAM_NO_FREE_INST", 0x4d, -1);
        AddConstEx(enum_id, "FC_IN_OUT_PARAM", 0x50, -1);
        AddConstEx(enum_id, "FC_OUT_PARAM", 0x51, -1);
        AddConstEx(enum_id, "FC_RETURN_PARAM", 0x52, -1);
        AddConstEx(enum_id, "FC_RETURN_PARAM_BASETYPE", 0x53, -1);
        AddConstEx(enum_id, "FC_DEREFERENCE", 0x54, -1);
        AddConstEx(enum_id, "FC_DIV_2", 0x55, -1);
        AddConstEx(enum_id, "FC_MULT_2", 0x56, -1);
        AddConstEx(enum_id, "FC_ADD_1", 0x57, -1);
        AddConstEx(enum_id, "FC_SUB_1", 0x58, -1);
        AddConstEx(enum_id, "FC_CALLBACK", 0x59, -1);
        AddConstEx(enum_id, "FC_CONSTANT_IID", 0x5a, -1);
        AddConstEx(enum_id, "FC_END", 0x5b, -1);
        AddConstEx(enum_id, "FC_PAD", 0x5c, -1);
        AddConstEx(enum_id, "FC_SPLIT_DEREFERENCE", 0x74, -1);
        AddConstEx(enum_id, "FC_SPLIT_DIV_2", 0x75, -1);
        AddConstEx(enum_id, "FC_SPLIT_MULT_2", 0x76, -1);
        AddConstEx(enum_id, "FC_SPLIT_ADD_1", 0x77, -1);
        AddConstEx(enum_id, "FC_SPLIT_SUB_1", 0x78, -1);
        AddConstEx(enum_id, "FC_SPLIT_CALLBACK", 0x79, -1);
        AddConstEx(enum_id, "FC_HARD_STRUCT", 0xb1, -1);
        AddConstEx(enum_id, "FC_TRANSMIT_AS_PTR", 0xb2, -1);
        AddConstEx(enum_id, "FC_REPRESENT_AS_PTR", 0xb3, -1);
        AddConstEx(enum_id, "FC_USER_MARSHAL", 0xb4, -1);
        AddConstEx(enum_id, "FC_PIPE", 0xb5, -1);
        AddConstEx(enum_id, "FC_BLKHOLE", 0xb6, -1);
        AddConstEx(enum_id, "FC_RANGE", 0xb7, -1);
        AddConstEx(enum_id, "FC_INT3264", 0xb8, -1);
        AddConstEx(enum_id, "FC_UINT3264", 0xb9, -1);
        AddConstEx(enum_id, "FC_END_OF_UNIVERSE", 0xba, -1);

        Message("[*] Finished adding items\n");
    }
    else
    {
        Message("[!] Problem getting new enum id\n");
    }
}
