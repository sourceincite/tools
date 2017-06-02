
    Howdy! This is the pymsrpc distribution/library/scripts/stuff.  The purpose of this is to allow a person to easily hit remote RPC endpoints and processes without having to deal with some of the complexities of marshalling and transport.  This is achieved in several parts.  The first are a series of scripts to automatically pull out RPC binaries from a directory, dump the idb, and then generate appropriate idl files for use.  Once that is accomplished you can then use the provided scripts or library to parse those and communicate with the foreign host.  This saves time by automatically creating the proper request and serializing the data in the wire format expected by Microsoft RPC endpoints.
    
    I hope this is of some use to someone out there.  We use it all the time in auditing RPC interfaces both in Microsoft products and third party software.  Although RPC is certainly a well traveled road vendors are still making rudimentary mistakes in the unmarshalling of data types (wchar strings in particular).
    
    A word of caution.  The NDR marshalling is not perfect.  It should do a majority of rpc opcodes but there are cases where it will not properly work.  This is being debugged and should be worked out in the near future.  If you feel so inclined to contribute it mostly has to do with structure padding and array serialization in structures.
    
    If you have any questions feel free to email them to me 'codyrpierce <> gmail.com'.
    
    Directories:
    
    pymsrpc/
        DEPENDENCIES.txt    - Necessary modules needed before using pymsrpc
        LICENSE.txt         - BSD license text
        READMEPLZ2ULOL.txt  - This file
        lexer.py            - The lexical def for the idl language
        ndr.py              - The NDR library for serializing data
        parse.py            - The parser which uses the lexer to build from a supplied idl
        rpc.py              - A wrapper for Impacket to ease the use of creating the transport
    scripts/
        BAD_STUB_DATA_2000              - A list of bad_stub_data exceptions in rpcrt4 on 2k
        BAD_STUB_DATA_XP                - A list of bad_stub_data exceptions in rpcrt4 on xp
        export_idl_from_idb.py          - Exports and idl from a directory of idbs
        export_pida_from_idb.py         - Exports a pida file from a directory of idbs
        ida_python.idc                  - Helper for launching the ida python plugin in batch
        idc_add_midl_enum.idc           - Adds the midl data type enum to your idb
        idl_dump.py                     - The main script that pulls all idls from a directory of rpc bins
        mida.idc                        - Helper for launching mida from IDA batch mode
        midl_format_pointer_flags.py    - Creates comments for a format string
        midl_param_desc_header_ida.py   - Creates comments for param description header in IDA
        midl_proc_header_ida.py         - Creates comments for procedure header in IDA
        midl_type_comment_ida.py        - Creates a comment at ScreenEA if a midl type is detected
        ndr_argument_type_monitor.py    - A pydbg script to monitor the unmarshalling of ndr for debugging
        rpc_pull_pipe.py                - Generates a template script from a binary by pulling the pipe name
    tests/
        debug.py            - A debug helper for printing hex and ndr data
        parse_test_np.py    - An example of using the library to send data over a named pipe
        parse_test_tcp.py   - An example of using the library to send data over a tcp endpoint