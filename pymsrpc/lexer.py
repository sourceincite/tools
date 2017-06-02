
'''
    lexer.py
    
    A lexer def for IDL files.
    
    (c) 2007 Aaron Portnoy - BSD License - See LICENSE.txt
'''

# Python imports
import sys

# Plex imports
try:
    from plex import *
except ImportError:
    print '[!] Problem importing Plex library please make sure you have this installed'
    print '[!] http://www.cosc.canterbury.ac.nz/greg.ewing/python/Plex/'
    sys.exit(-1)


letter      = Range("AZaz")
digit       = Range("09")
whitespace  = Any(" \t\r\n")

def lexify():

    # Generics
    generic_type_void               = Str("void")
    generic_type_hyper              = Str("hyper")
    generic_type_long               = Str("long")
    generic_type_short              = Str("short")
    generic_type_small              = Str("small")
    generic_type_byte               = Str("byte")
    generic_type_union              = Str("union")
    generic_type_range              = (Str("[range(") + Rep1(digit) + Str(",") + Rep1(digit) + Str(")]"))
    generic_type_char               = Str("char")
    generic_type_float              = Str("float")
    generic_type_double             = Str("double")
    generic_type_pipe               = Str("pipe")
    generic_type_handle_t           = Str("handle_t")
    generic_error_status_t          = Str("error_status_t")
    generic_type_wchar_t            = Str("wchar_t")
    generic_type_struct             = Str("struct")
    generic_user_marshal            = Str("[user_marshal(") + Rep1(digit) + Str(")]")
    generic_UNKNOWN                 = Str("UNKNOWN_TYPE_") + Rep1(letter | digit)

    generic_single_unique           = Str("*")
    generic_double_unique           = Str("**")
    generic_triple_unique           = Str("***")
    generic_struct_name             = Str("struct_") + Rep1(letter | digit)
    generic_union_name              = Str("union_") + Rep1(letter | digit)
    generic_enum16                  = Str("enum16")
    generic_enum32                  = Str("enum32")
    generic_unsigned                = Str("unsigned")
    generic_string                  = Str("[string]")
    generic_unique                  = Str("[unique]")
    generic_pointer                 = Str("[ptr]")
    generic_reference               = Str("[ref]")
    generic_interface               = Str("interface(") + Rep1(letter | digit | Str("-")) + Str(")")
    generic_byte_count              = Str("byte_count(") + Rep1(Any("*_)/") | digit | letter)


    # Arrays
    array_fixed                     = Str("[") + Rep1(digit) + Str("]")
    array_size_is                   = Str("size_is(") + Rep1(Any("*_)/") | digit | letter)
    array_length_is                 = Str("length_is(") + Rep1(Any("*_)/") | digit | letter)
    array_first_is                  = Str("first_is(") + Rep1(Any("*_)/") | digit | letter)
    array_last_is                   = Str("last_is(") + Rep1(Any("*_)/") | digit | letter)
    array_byte_count                = Str("byte_count(") + Rep(Any("*_)/") | digit | letter)
    array_empty                     = Str("[]")

    # UUID tokens
    uuid                            = Str("uuid(") + Rep1(letter | digit | Str("-")) + Str(")")
    #uuid_end                        = Str("}") + Rep(whitespace) + Rep(AnyBut("us*/")) # u = } union, s = } struct
    uuid_end                        = Str("}") + Rep(Any("\r\n"))
    
    # Version token
    version                         = Str("version(") + Rep1(digit) + Str(".") + Rep1(digit) + Str(")")

    # Opcode header tokens
    begin_comment                   = Str("/*")
    end_comment                     = Str("*/")
    opnum                           = Str("opcode: 0x") + Rep1(letter | digit)
    opcode_address                  = Str("address: 0x") + Rep1(letter | digit)
    opcode_sub                      = (Str("long ") | Str("short ") | Str("small ") | Str("void ") | Str("error_status_t ")) + Rep1(Any("_ ") | digit | letter) + Str(" ")
    #opcode_symbol_sub              = AnyBut("sub") + Rep(Any("_") | letter | digit) + Str("(")

    # Opcode elements
    opcode_element_out              = Str("[out]")
    opcode_element_in               = Str("[in]")
    opcode_element_in_out           = Str("[in, out]")
    opcode_element_context_handle   = Str("[context_handle]")
    opcode_element_switch_is        = Str("[switch_is(") + Rep1((Any("_/*") | letter | digit)) + Str(")]")
    opcode_element_end              = Rep(Str(",")) + Rep1(Any("\r\n"))
    opcode_element_argument_name    = Str("arg_") + Rep1(letter | digit)
    opcode_element_array_fixed      = Str("[") + Rep1(digit) + Str("]")
    opcode_element_single_unique    = generic_single_unique
    opcode_element_double_unique    = generic_double_unique
    opcode_element_triple_unique    = generic_triple_unique
    opcode_element_array_size_is    = Str("size_is(") + Rep1(Any("*_/") | digit | letter) + Str(")")
    opcode_element_array_length_is  = Str("length_is(") + Rep1(Any("*_/") | digit | letter) + Str(")")
    opcode_element_array_first_is   = Str("first_is(") + Rep1(Any("*_/") | digit | letter) + Str(")")
    opcode_element_array_last_is    = Str("last_is(") + Rep1(Any("*_/") | digit | letter) + Str(")")
    opcode_element_array_max_is     = Str("max_is(") + Rep1(Any("*_/") | digit | letter) + Str(")")
    opcode_end                      = Str(");")

    # Structure header tokens
    structure_typedef               = Str("typedef struct") + whitespace + generic_struct_name

    # Structure elements
    structure_element_name          = Str("elem_") + Rep1(letter | digit)
    structure_element_array_name    = Str("elem_") + Rep1(letter | digit)
    structure_element_array_fixed   = Str("[") + Rep1(digit) + Str("]")
    structure_element_switch_is     = Str("[switch_is(") + Rep1((Any("_/*") | letter | digit)) + Str(")]")


    # Union header tokens
    union_typedef                   = Str("typedef [switch_type(")
    union_declaration               = Str(")] union union_") + Rep1(digit | letter) + Str(" {")

    # Union cases
    union_case                      = Str("[case(") + Rep1(digit) + Str(")]")
    union_default                   = Str("[default]")
    union_element_name              = Str("elem_") + Rep1(letter | digit)
    union_element_switch_is         = Str("[switch_is(") + Rep1((Any("_/*") | letter | digit)) + Str(")]")


    # Ignore these tokens
    ignore_mida_interface           = Str("interface mIDA_interface") + Rep(whitespace)
    ignore_unknown_sub              = Str("unknown sub_") + Rep1(digit | letter) + Rep(whitespace)

    # Misc
    misc_left_paren                 = Str("(")
    misc_right_paren                = Str(")")
    misc_left_bracket               = Str("[")
    misc_right_bracket              = Str("]")
    misc_left_curly                 = Str("{")
    misc_right_curly                = Str("}")
    misc_semicolon                  = Str(";")
    misc_comma                      = Str(",")

    lexicon = Lexicon([
    
        # Skip big comment blocks (like the mIDA header)
        (Str("/*") + Rep1(Any("\n\r")),   Begin("big_comment")),
        State("big_comment", [
            (Rep1(whitespace) + Str("*/") + Rep1(Any("\n\r")),    Begin("")),
            (AnyChar,   IGNORE)
        ]),

        # UUID
        (uuid,                          "uuid"),
    
        # Version
        (version,                       "version"),

        # Opcode header tokens
        (begin_comment,                 "begin_comment"),
        (end_comment,                   "end_comment"),


        #########################################################################
        # BEGIN OPCODE
        (opnum,                             "opnum"),
        State("opcode", [
            #(opcode_end,                    Begin("")),
            (opcode_end,                    "opcode_end"),
            (Any(" \t"),                    IGNORE),
            (begin_comment,                 "begin_comment"),
            (end_comment,                   "end_comemnt"),
            (opcode_address,                "opcode_address"),
            (opcode_sub,                    "opcode_sub"),
            #(opcode_symbol_sub,             "opcode_symbol_sub"),

            # Opcode element tokens
            (opcode_element_out,            "opcode_element_out"),
            (opcode_element_in,             "opcode_element_in"),
            (opcode_element_in_out,         "opcode_element_in_out"),
            (opcode_element_context_handle, "opcode_element_context_handle"),
            (opcode_element_switch_is,      "opcode_element_switch_is"),
            (opcode_element_end,            "opcode_element_end"),
            (opcode_element_argument_name,  "opcode_element_argument_name"),
            (opcode_element_single_unique,  "opcode_element_single_unique"),
            (opcode_element_double_unique,  "opcode_element_double_unique"),
            (opcode_element_triple_unique,  "opcode_element_triple_unique"),
            (opcode_element_array_fixed,    "opcode_element_array_fixed"),

            (opcode_element_array_size_is,  "opcode_element_array_size_is"),
            
            (opcode_element_array_length_is,"opcode_element_array_length_is"),
            (opcode_element_array_first_is, "opcode_element_array_first_is"),
            (opcode_element_array_last_is,  "opcode_element_array_last_is"),  
            (opcode_element_array_max_is,   "opcode_element_array_max_is"),   
            
            (generic_type_void,               "opcode_element_void"),
            (generic_type_hyper,              "opcode_element_hyper"),
            (generic_type_long,               "opcode_element_long"),
            (generic_type_short,              "opcode_element_short"),
            (generic_type_small,              "opcode_element_small"),
            (generic_type_byte,               "opcode_element_byte"),
            (generic_type_union,              "opcode_element_union"),
            (generic_type_range,              "opcode_element_range"),
            (generic_type_char,               "opcode_element_char"),
            (generic_type_float,              "opcode_element_float"),
            (generic_type_double,             "opcode_element_double"),
            (generic_type_pipe,               "opcode_element_pipe"),
            (generic_type_handle_t,           "opcode_element_handle_t"),
            (generic_error_status_t,          "opcode_element_error_status_t"),
            (generic_type_wchar_t,            "opcode_element_wchar_t"),
            (generic_type_struct,             "opcode_element_struct"),

            (generic_single_unique,           "opcode_element_single_unique"),
            (generic_double_unique,           "opcode_element_double_unique"),
            (generic_triple_unique,           "opcode_element_triple_unique"),
            (generic_struct_name,             "opcode_element_struct_name"),
            (generic_union_name,              "opcode_element_union_name"),
            (generic_enum16,                  "opcode_element_enum16"),
            (generic_enum32,                  "opcode_element_enum32"),
            (generic_unsigned,                "opcode_element_unsigned"),
            (generic_string,                  "opcode_element_string"),
            (generic_unique,                  "opcode_element_unique"),
            (generic_pointer,                 "opcode_element_ptr"),
            (generic_reference,               "opcode_element_ref"),
            (generic_interface,               "opcode_element_interface"),
            (generic_byte_count,              "opcode_element_byte_count"),
            (generic_UNKNOWN,                 "generic_UNKNOWN"),

            (misc_comma,                      IGNORE),
            (misc_left_paren,                 IGNORE),
            (misc_right_curly,                "uuid_end"),
            (misc_left_bracket,               IGNORE),
            (misc_right_bracket,              IGNORE),
            (Str("(") + Rep1(Any("\n\r")),    "opcode_begin"),
            

        ]),
        # END OPCODE
        #########################################################################
        
        #########################################################################
        # BEGIN STRUCTURE
        (structure_typedef,               "structure_typedef"), 
        State("structure", [
        
            (structure_element_name,          "structure_element_name"),      
            (structure_element_array_name,    "structure_element_name"),
            (structure_element_array_fixed,   "structure_element_array_fixed"),
            (structure_element_switch_is,     "structure_element_switch_is"),
            
            (generic_type_hyper,              "structure_element_hyper"),
            (generic_type_void,               "structure_element_void"),
            (generic_type_long,               "structure_element_long"),
            (generic_type_short,              "structure_element_short"),
            (generic_type_small,              "structure_element_small"),
            (generic_type_byte,               "structure_element_byte"),
            (generic_type_union,              "structure_element_union"),
            (generic_type_range,              "structure_element_range"),
            (generic_type_char,               "structure_element_char"),
            (generic_type_float,              "structure_element_float"),
            (generic_type_double,             "structure_element_double"),
            (generic_type_pipe,               "structure_element_pipe"),
            (generic_type_handle_t,           "structure_element_handle_t"),
            (generic_error_status_t,          "structure_element_error_status_t"),
            (generic_type_wchar_t,            "structure_element_wchar_t"),
            (generic_type_struct,             "structure_element_struct"),
            (generic_user_marshal,            "generic_user_marshal"),
                                               
            (generic_single_unique,           "structure_element_single_unique"),
            (generic_double_unique,           "structure_element_double_unique"),
            (generic_triple_unique,           "structure_element_triple_unique"),
            (generic_struct_name,             "structure_element_struct_name"),
            (generic_union_name,              "structure_element_union_name"),
            (generic_enum16,                  "structure_element_enum16"),
            (generic_enum32,                  "structure_element_enum32"),
            (generic_unsigned,                "structure_element_unsigned"),
            (generic_string,                  "structure_element_string"),
            (generic_unique,                  "structure_element_unique"),
            (generic_pointer,                 "structure_element_ptr"),
            (generic_reference,               "structure_element_ref"),
            (generic_interface,               "structure_element_interface"),
            (generic_byte_count,              "structure_element_byte_count"),
            
            (array_fixed,                     "structure_element_array_fixed"),
            (array_size_is,                   "structure_element_array_size_is"),
            (array_length_is,                 "structure_element_array_length_is"),
            (array_first_is,                  "structure_element_array_first_is"),
            (array_last_is,                   "structure_element_array_last_is"),
            (array_byte_count,                "structure_element_array_byte_count"),    
            
            (generic_UNKNOWN,                 "generic_UNKNOWN"),
            (begin_comment,                   IGNORE),
            (end_comment,                     IGNORE),
            (whitespace,                      IGNORE),
            (misc_comma,                      IGNORE),
            (misc_semicolon,                  "structure_element_end"),
            (misc_left_bracket,               IGNORE),
            (misc_right_bracket,              IGNORE),
            (misc_left_curly,                 IGNORE),
            (misc_right_curly,                "structure_end"),
        ]),

        #########################################################################
        # BEGIN UNION
        (union_typedef,               "union_typedef"), 
        State("union", [
            (whitespace,                      IGNORE),
            
            (union_declaration,               "union_declaration"),
            (union_case,                      "union_case"),
            (union_default,                   "union_default"),
            (union_element_name,              "union_element_name"),
            
            (generic_type_long,               "union_element_long"),
            (generic_type_hyper,              "union_element_hyper"),
            (generic_type_void,               "union_element_void"),
            (generic_type_long,               "union_element_long"),
            (generic_type_short,              "union_element_short"),
            (generic_type_small,              "union_element_small"),
            (generic_type_byte,               "union_element_byte"),
            (generic_type_union,              "union_element_union"),
            (generic_type_range,              "union_element_range"),
            (generic_type_char,               "union_element_char"),
            (generic_type_float,              "union_element_float"),
            (generic_type_double,             "union_element_double"),
            (generic_type_pipe,               "union_element_pipe"),
            (generic_type_handle_t,           "union_element_handle_t"),
            (generic_error_status_t,          "union_element_error_status_t"),
            (generic_type_wchar_t,            "union_element_wchar_t"),
            (generic_type_struct,             "union_element_struct"),
            (union_element_switch_is,         "union_element_switch_is"),
            (generic_user_marshal,            "generic_user_marshal"),
                                               
            (generic_single_unique,           "union_element_single_unique"),
            (generic_double_unique,           "union_element_double_unique"),
            (generic_triple_unique,           "union_element_triple_unique"),
            (generic_struct_name,             "union_element_struct_name"),
            (generic_union_name,              "union_element_union_name"),
            (generic_enum16,                  "union_element_enum16"),
            (generic_enum32,                  "union_element_enum32"),
            (generic_unsigned,                "union_element_unsigned"),
            (generic_string,                  "union_element_string"),
            (generic_unique,                  "union_element_unique"),
            (generic_pointer,                 "union_element_ptr"),
            (generic_reference,               "union_element_ref"),
            (generic_interface,               "union_element_interface"),
            (generic_byte_count,              "union_element_byte_count"),

            (array_fixed,                     "union_element_array_fixed"),
            (array_size_is,                   "union_element_array_size_is"),
            (array_length_is,                 "union_element_array_length_is"),
            (array_first_is,                  "union_element_array_first_is"),
            (array_last_is,                   "union_element_array_last_is"),
            (array_byte_count,                "union_element_array_byte_count"), 

            (generic_UNKNOWN,                 "generic_UNKNOWN"),
            (begin_comment,                   "begin_comment"),
            (end_comment,                     "end_comment"),
            (misc_semicolon,                  "union_element_end"),
            (misc_right_curly,                "union_end"),
            (misc_left_bracket,               "misc_left_bracket"),
            (misc_right_bracket,              "misc_right_bracket"),


        ]),

        (generic_type_void,               "generic_type_void"),
        (generic_type_hyper,              "generic_type_hyper"),
        (generic_type_long,               "generic_type_long"),
        (generic_type_short,              "generic_type_short"),
        (generic_type_small,              "generic_type_small"),
        (generic_type_byte,               "generic_type_byte"),
        (generic_type_union,              "generic_type_union"),
        (generic_type_range,              "generic_type_range"),
        (generic_type_char,               "generic_type_char"),
        (generic_type_float,              "generic_type_float"),
        (generic_type_double,             "generic_type_double"),
        (generic_type_pipe,               "generic_type_pipe"),
        (generic_type_handle_t,           "generic_type_handle_t"),
        (generic_error_status_t,          "generic_type_error_status_t"),
        (generic_type_wchar_t,            "generic_type_wchar_t"),
        (generic_type_struct,             "generic_type_struct"),
                                          
        # Structure elements              
        (structure_element_name,          "structure_element_name"),
        (structure_element_array_name,    "structure_element_array_name"),
        (structure_element_switch_is,     "structure_element_switch_is"),
                                          
        # Union header tokens             
        (union_typedef,                   "union_typedef"),
                                          
        # Union cases                     
        (union_case,                      "union_case"),
        (union_default,                   "union_default"),
                                          
        # Array tokens                    
        (array_fixed,                     "array_fixed"),
        (array_size_is,                   "array_size_is"),
        (array_length_is,                 "array_length_is"),
        (array_first_is,                  "array_first_is"),
        (array_last_is,                   "array_last_is"),
        (array_byte_count,                "array_byte_count"),
                                          
        # Generic stuff                   
        (whitespace,                      IGNORE), # XXX: perhaps change to "space" ?
        (generic_type_struct,             "generic_type_struct"),
        (generic_user_marshal,            "generic_user_marshal"),
        (generic_UNKNOWN,                 "generic_UNKNOWN"),
        (generic_type_union,              "generic_type_union"),
        (generic_single_unique,           "generic_single_unique"),
        (generic_double_unique,           "generic_double_unique"),
        (generic_triple_unique,           "generic_triple_unique"),
        (generic_struct_name,             "generic_struct_name"),
        (generic_union_name,              "generic_union_name"),
                                          
                                          
        (generic_enum16,                  "generic_enum16"),
        (generic_enum32,                  "generic_enum32"),
        (generic_unsigned,                "generic_unsigned"),
        (generic_string,                  "generic_string"),
        (generic_unique,                  "generic_unique"),
        (generic_pointer,                 "generic_ptr"),
        (generic_reference,               "generic_ref"),
        (generic_interface,               "generic_interface"),
                                          
        # Misc                            
        (misc_left_paren,                 "misc_left_paren"),
        (misc_right_paren,                "misc_right_paren"),
        (misc_right_bracket,              "misc_right_bracket"),
        (misc_left_bracket,               "misc_left_bracket"),
        (misc_right_curly,                "misc_right_curly"),
        (misc_left_curly,                 "misc_left_curly"),
        (misc_semicolon,                  "misc_semicolon"),
        (misc_comma,                      IGNORE),
        
        (uuid_end,                        "uuid_end"),
                                          
                                          
        # Ignores                         
        (ignore_mida_interface,           IGNORE),
        (ignore_unknown_sub,              IGNORE),

    ])

    return lexicon

