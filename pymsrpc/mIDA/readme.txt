------------------------------------------------------------------------------------
mIDA v1.0.10 - MIDL Decompiler for IDA

(C) 2008 Nicolas Pouvesle <npouvesle@tenablesecurity.com> / Tenable Network Security
------------------------------------------------------------------------------------


WHAT IS mIDA?

mIDA is an IDA plugin which extracts RPC interfaces and recreates
the associated IDL file.
mIDA supports inline, interpreted and fully interpreted server stubs.


INSTALLATION

Just copy mida.plw to your IDA plugin directory.


HOW TO USE IT?

mIDA only works with the Windows GUI version of IDA (5.2 or later).
The plugin can be launched via the plugin menu or by using the shortcut
CTRL+7.

mIDA displays each interface inside a separate list dialog box.
Each function can be edited or decompiled (right click).
Format string addresses must only be changed if you suspect that
mIDA does not use the correct entry.


NOTE: mIDA can save the output to a file instead of using windows
when the 'ofile' option is given.


CHANGELOG

v1.0.10
------

- Adds support for NDR version 0x50004

v1.0.9
------

- Really fix FC_XSTRUCT with FC_ALIGNMX element (Thanks to Cody Pierce)
- Add debug statements if the key "HKLM\SOFTWARE\Tenable\mIDA - Debug" is set to 1

v1.0.8
------

- Display [ref] if set
- Fix FC_XSTRUCT with FC_ALIGNMX element (Thanks to Cody Pierce)

v1.0.7
------

- Add support for FC_CVSTRUCT
- Ndr version 0x10001 can be an interpreted stub too
- Fix encapsulated union display to work with midl.exe

v1.0.6
------

- Fix an access violation error if the NDR version is not supported (Thanks to Alexander Sotirov)
- Fix Union if multiple cases refer to the same element
- Fix field reference if the structure contains an encapsulated union
- Add support for FC_USER_MARSHAL attribute (just display the size to send)
- Add support for NDR version 0x60001 used in Vista:
 * Add support for FC_SUPPLEMENT
 * Add support for FC_FORCED_BOGUS_STRUCT
 * Add support for FC_EXPR (complex size_is/length_is are now encoded using a Reverse Polish Notation)
 * Add support for new range type


v1.0.5
------

- Bugfix for special return values for inline stubs

v1.0.4
------

- Display FC_CALLBACK address instead of '?'
- Generated IDL code can now be compiled with a midl compiler
- FC_ENUM16 is now displayed as a short
- Add support for obsolete keywords FC_ALIGNMX
- Add support for FC_BYTE_COUNT_POINTER
- Fix function name if a pdb file is used in IDA
- Fix the address of the argument structure in the edit box
- Wait that IDA has processed enerything in the queues before scanning
- If RPC functions are not defined as function, ask IDA to define them (useful for inline functions)
- Raise an Exception if the loop recursion limit is reached
- Display information about the RPC stub in the decompilation window
- Added ofile option for bash mode
- Ported to IDA5.0

v1.0.3
------

- Call msg instead of error if the plugin is skipped (else it closes IDA)

v1.0.2
------

- Bugfix with some arguments

v1.0.1
------

- Display the opcode in the IDL output

v1.0.0
------

- Initial release