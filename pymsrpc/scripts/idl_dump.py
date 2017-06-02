#!c:\python\python.exe
#
# Aaron Portnoy
# TippingPoint Security Research Team
# (c) 2007
#

# the following is ripped from pefile, thanks ero
# my code begins on line 2318
####################################################################################################

# -*- coding: Latin-1 -*-
"""pefile, Portable Executable reader module


All the PE file basic structures are available with their default names
as attributes of the instance returned.

Processed elements such as the import table are made available with lowercase
names, to differentiate them from the upper case basic structure names.

pefile has been tested against the limits of valid PE headers, that is, malware.
Lots of packed malware attempt to abuse the format way beyond its standard use.
To the best of my knowledge most of the abuses are handled gracefully.

Copyright (c) 2005, 2006 Ero Carrera <ero@dkbza.org>

All rights reserved.

For detailed copyright information see the file COPYING in
the root of the distribution archive.
"""

__author__ = 'Ero Carrera'
__version__ = '1.2'
__contact__ = 'ero@dkbza.org'

import os
import struct
import time
import exceptions


fast_load = False

IMAGE_DOS_SIGNATURE             = 0x5A4D
IMAGE_OS2_SIGNATURE             = 0x454E
IMAGE_OS2_SIGNATURE_LE          = 0x454C
IMAGE_VXD_SIGNATURE             = 0x454C
IMAGE_NT_SIGNATURE              = 0x00004550
IMAGE_NUMBEROF_DIRECTORY_ENTRIES= 16
IMAGE_ORDINAL_FLAG              = 0x80000000L
IMAGE_ORDINAL_FLAG64            = 0x8000000000000000L
OPTIONAL_HEADER_MAGIC_PE        = 0x10b
OPTIONAL_HEADER_MAGIC_PE_PLUS   = 0x20b


directory_entry_types = [
    ('IMAGE_DIRECTORY_ENTRY_EXPORT',        0),
    ('IMAGE_DIRECTORY_ENTRY_IMPORT',        1),
    ('IMAGE_DIRECTORY_ENTRY_RESOURCE',      2),
    ('IMAGE_DIRECTORY_ENTRY_EXCEPTION',     3),
    ('IMAGE_DIRECTORY_ENTRY_SECURITY',      4),
    ('IMAGE_DIRECTORY_ENTRY_BASERELOC',     5),
    ('IMAGE_DIRECTORY_ENTRY_DEBUG',         6),
    ('IMAGE_DIRECTORY_ENTRY_COPYRIGHT',     7),
    ('IMAGE_DIRECTORY_ENTRY_GLOBALPTR',     8),
    ('IMAGE_DIRECTORY_ENTRY_TLS',           9),
    ('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG',   10),
    ('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT',  11),
    ('IMAGE_DIRECTORY_ENTRY_IAT',           12),
    ('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT',  13),
    ('IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR',14),
    ('IMAGE_DIRECTORY_ENTRY_RESERVED',      15) ]

DIRECTORY_ENTRY = dict([(e[1], e[0]) for e in directory_entry_types]+directory_entry_types)
 

image_characteristics = [
    ('IMAGE_FILE_RELOCS_STRIPPED',          0x0001),
    ('IMAGE_FILE_EXECUTABLE_IMAGE',         0x0002),
    ('IMAGE_FILE_LINE_NUMS_STRIPPED',       0x0004),
    ('IMAGE_FILE_LOCAL_SYMS_STRIPPED',      0x0008),
    ('IMAGE_FILE_AGGRESIVE_WS_TRIM',        0x0010),
    ('IMAGE_FILE_LARGE_ADDRESS_AWARE',      0x0020),
    ('IMAGE_FILE_16BIT_MACHINE',            0x0040),
    ('IMAGE_FILE_BYTES_REVERSED_LO',        0x0080),
    ('IMAGE_FILE_32BIT_MACHINE',            0x0100),
    ('IMAGE_FILE_DEBUG_STRIPPED',           0x0200),
    ('IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP',  0x0400),
    ('IMAGE_FILE_NET_RUN_FROM_SWAP',        0x0800),
    ('IMAGE_FILE_SYSTEM',                   0x1000),
    ('IMAGE_FILE_DLL',                      0x2000),
    ('IMAGE_FILE_UP_SYSTEM_ONLY',           0x4000),
    ('IMAGE_FILE_BYTES_REVERSED_HI',        0x8000) ]

IMAGE_CHARACTERISTICS = dict([(e[1], e[0]) for e in
    image_characteristics]+image_characteristics)

    
section_characteristics = [
    ('IMAGE_SCN_CNT_CODE',                  0x00000020),
    ('IMAGE_SCN_CNT_INITIALIZED_DATA',      0x00000040),
    ('IMAGE_SCN_CNT_UNINITIALIZED_DATA',    0x00000080),
    ('IMAGE_SCN_LNK_OTHER',                 0x00000100),
    ('IMAGE_SCN_LNK_INFO',                  0x00000200),
    ('IMAGE_SCN_LNK_REMOVE',                0x00000800),
    ('IMAGE_SCN_LNK_COMDAT',                0x00001000),
    ('IMAGE_SCN_MEM_FARDATA',               0x00008000),
    ('IMAGE_SCN_MEM_PURGEABLE',             0x00020000),
    ('IMAGE_SCN_MEM_16BIT',                 0x00020000),
    ('IMAGE_SCN_MEM_LOCKED',                0x00040000),
    ('IMAGE_SCN_MEM_PRELOAD',               0x00080000),
    ('IMAGE_SCN_ALIGN_1BYTES',              0x00100000),
    ('IMAGE_SCN_ALIGN_2BYTES',              0x00200000),
    ('IMAGE_SCN_ALIGN_4BYTES',              0x00300000),
    ('IMAGE_SCN_ALIGN_8BYTES',              0x00400000),
    ('IMAGE_SCN_ALIGN_16BYTES',             0x00500000),
    ('IMAGE_SCN_ALIGN_32BYTES',             0x00600000),
    ('IMAGE_SCN_ALIGN_64BYTES',             0x00700000),
    ('IMAGE_SCN_ALIGN_128BYTES',            0x00800000),
    ('IMAGE_SCN_ALIGN_256BYTES',            0x00900000),
    ('IMAGE_SCN_ALIGN_512BYTES',            0x00A00000),
    ('IMAGE_SCN_ALIGN_1024BYTES',           0x00B00000),
    ('IMAGE_SCN_ALIGN_2048BYTES',           0x00C00000),
    ('IMAGE_SCN_ALIGN_4096BYTES',           0x00D00000),
    ('IMAGE_SCN_ALIGN_8192BYTES',           0x00E00000),
    ('IMAGE_SCN_ALIGN_MASK',                0x00F00000),
    ('IMAGE_SCN_LNK_NRELOC_OVFL',           0x01000000),
    ('IMAGE_SCN_MEM_DISCARDABLE',           0x02000000),
    ('IMAGE_SCN_MEM_NOT_CACHED',            0x04000000),
    ('IMAGE_SCN_MEM_NOT_PAGED',             0x08000000),
    ('IMAGE_SCN_MEM_SHARED',                0x10000000),
    ('IMAGE_SCN_MEM_EXECUTE',               0x20000000),
    ('IMAGE_SCN_MEM_READ',                  0x40000000),
    ('IMAGE_SCN_MEM_WRITE',                 0x80000000L) ]
 
SECTION_CHARACTERISTICS = dict([(e[1], e[0]) for e in
    section_characteristics]+section_characteristics)


debug_types = [
    ('IMAGE_DEBUG_TYPE_UNKNOWN',        0),
    ('IMAGE_DEBUG_TYPE_COFF',           1),
    ('IMAGE_DEBUG_TYPE_CODEVIEW',       2),
    ('IMAGE_DEBUG_TYPE_FPO',            3),
    ('IMAGE_DEBUG_TYPE_MISC',           4),
    ('IMAGE_DEBUG_TYPE_EXCEPTION',      5),
    ('IMAGE_DEBUG_TYPE_FIXUP',          6),
    ('IMAGE_DEBUG_TYPE_OMAP_TO_SRC',    7),
    ('IMAGE_DEBUG_TYPE_OMAP_FROM_SRC',  8),
    ('IMAGE_DEBUG_TYPE_BORLAND',        9),
    ('IMAGE_DEBUG_TYPE_RESERVED10',     10) ]

DEBUG_TYPE = dict([(e[1], e[0]) for e in debug_types]+debug_types)


subsystem_types = [
    ('IMAGE_SUBSYSTEM_UNKNOWN',     0),
    ('IMAGE_SUBSYSTEM_NATIVE',      1),
    ('IMAGE_SUBSYSTEM_WINDOWS_GUI', 2),
    ('IMAGE_SUBSYSTEM_WINDOWS_CUI', 3),
    ('IMAGE_SUBSYSTEM_OS2_CUI',     5),
    ('IMAGE_SUBSYSTEM_POSIX_CUI',   7),
    ('IMAGE_SUBSYSTEM_XBOX',        14)]

SUBSYSTEM_TYPE = dict([(e[1], e[0]) for e in subsystem_types]+subsystem_types)


machine_types = [
    ('IMAGE_FILE_MACHINE_UNKNOWN',  0),
    ('IMAGE_FILE_MACHINE_AM33',     0x1d3),
    ('IMAGE_FILE_MACHINE_AMD64',    0x8664),
    ('IMAGE_FILE_MACHINE_ARM',      0x1c0),
    ('IMAGE_FILE_MACHINE_EBC',      0xebc),
    ('IMAGE_FILE_MACHINE_I386',     0x14c),
    ('IMAGE_FILE_MACHINE_IA64',     0x200),
    ('IMAGE_FILE_MACHINE_MR32',     0x9041),
    ('IMAGE_FILE_MACHINE_MIPS16',   0x266),
    ('IMAGE_FILE_MACHINE_MIPSFPU',  0x366),
    ('IMAGE_FILE_MACHINE_MIPSFPU16',0x466),
    ('IMAGE_FILE_MACHINE_POWERPC',  0x1f0),
    ('IMAGE_FILE_MACHINE_POWERPCFP',0x1f1),
    ('IMAGE_FILE_MACHINE_R4000',    0x166),
    ('IMAGE_FILE_MACHINE_SH3',      0x1a2),
    ('IMAGE_FILE_MACHINE_SH3DSP',   0x1a3),
    ('IMAGE_FILE_MACHINE_SH4',      0x1a6),
    ('IMAGE_FILE_MACHINE_SH5',      0x1a8),
    ('IMAGE_FILE_MACHINE_THUMB',    0x1c2),
    ('IMAGE_FILE_MACHINE_WCEMIPSV2',0x169),
 ]

MACHINE_TYPE = dict([(e[1], e[0]) for e in machine_types]+machine_types)


relocation_types = [
    ('IMAGE_REL_BASED_ABSOLUTE',        0),
    ('IMAGE_REL_BASED_HIGH',            1),
    ('IMAGE_REL_BASED_LOW',             2),
    ('IMAGE_REL_BASED_HIGHLOW',         3),
    ('IMAGE_REL_BASED_HIGHADJ',         4),
    ('IMAGE_REL_BASED_MIPS_JMPADDR',    5),
    ('IMAGE_REL_BASED_SECTION',         6),
    ('IMAGE_REL_BASED_REL',             7),
    ('IMAGE_REL_BASED_MIPS_JMPADDR16',  9),
    ('IMAGE_REL_BASED_IA64_IMM64',      9),
    ('IMAGE_REL_BASED_DIR64',           10),
    ('IMAGE_REL_BASED_HIGH3ADJ',        11) ]

RELOCATION_TYPE = dict([(e[1], e[0]) for e in relocation_types]+relocation_types)


# Resource types
resource_type = [
    ('RT_CURSOR',          1),
    ('RT_BITMAP',          2),
    ('RT_ICON',            3),
    ('RT_MENU',            4),
    ('RT_DIALOG',          5),
    ('RT_STRING',          6),
    ('RT_FONTDIR',         7),
    ('RT_FONT',            8),
    ('RT_ACCELERATOR',     9),
    ('RT_RCDATA',          10),
    ('RT_MESSAGETABLE',    11),
    ('RT_GROUP_CURSOR',    12),
    ('RT_GROUP_ICON',      14),
    ('RT_VERSION',         16),
    ('RT_DLGINCLUDE',      17),
    ('RT_PLUGPLAY',        19),
    ('RT_VXD',             20),
    ('RT_ANICURSOR',       21),
    ('RT_ANIICON',         22),
    ('RT_HTML',            23),
    ('RT_MANIFEST',        24) ]

RESOURCE_TYPE = dict([(e[1], e[0]) for e in resource_type]+resource_type)

    
# Language definitions
lang = [
 ('LANG_NEUTRAL',       0x00),
 ('LANG_INVARIANT',     0x7f),
 ('LANG_AFRIKAANS',     0x36),
 ('LANG_ALBANIAN',      0x1c),
 ('LANG_ARABIC',        0x01),
 ('LANG_ARMENIAN',      0x2b),
 ('LANG_ASSAMESE',      0x4d),
 ('LANG_AZERI',         0x2c),
 ('LANG_BASQUE',        0x2d),
 ('LANG_BELARUSIAN',    0x23),
 ('LANG_BENGALI',       0x45),
 ('LANG_BULGARIAN',     0x02),
 ('LANG_CATALAN',       0x03),
 ('LANG_CHINESE',       0x04),
 ('LANG_CROATIAN',      0x1a),
 ('LANG_CZECH',         0x05),
 ('LANG_DANISH',        0x06),
 ('LANG_DIVEHI',        0x65),
 ('LANG_DUTCH',         0x13),
 ('LANG_ENGLISH',       0x09),
 ('LANG_ESTONIAN',      0x25),
 ('LANG_FAEROESE',      0x38),
 ('LANG_FARSI',         0x29),
 ('LANG_FINNISH',       0x0b),
 ('LANG_FRENCH',        0x0c),
 ('LANG_GALICIAN',      0x56),
 ('LANG_GEORGIAN',      0x37),
 ('LANG_GERMAN',        0x07),
 ('LANG_GREEK',         0x08),
 ('LANG_GUJARATI',      0x47),
 ('LANG_HEBREW',        0x0d),
 ('LANG_HINDI',         0x39),
 ('LANG_HUNGARIAN',     0x0e),
 ('LANG_ICELANDIC',     0x0f),
 ('LANG_INDONESIAN',    0x21),
 ('LANG_ITALIAN',       0x10),
 ('LANG_JAPANESE',      0x11),
 ('LANG_KANNADA',       0x4b),
 ('LANG_KASHMIRI',      0x60),
 ('LANG_KAZAK',         0x3f),
 ('LANG_KONKANI',       0x57),
 ('LANG_KOREAN',        0x12),
 ('LANG_KYRGYZ',        0x40),
 ('LANG_LATVIAN',       0x26),
 ('LANG_LITHUANIAN',    0x27),
 ('LANG_MACEDONIAN',    0x2f),
 ('LANG_MALAY',         0x3e),
 ('LANG_MALAYALAM',     0x4c),
 ('LANG_MANIPURI',      0x58),
 ('LANG_MARATHI',       0x4e),
 ('LANG_MONGOLIAN',     0x50),
 ('LANG_NEPALI',        0x61),
 ('LANG_NORWEGIAN',     0x14),
 ('LANG_ORIYA',         0x48),
 ('LANG_POLISH',        0x15),
 ('LANG_PORTUGUESE',    0x16),
 ('LANG_PUNJABI',       0x46),
 ('LANG_ROMANIAN',      0x18),
 ('LANG_RUSSIAN',       0x19),
 ('LANG_SANSKRIT',      0x4f),
 ('LANG_SERBIAN',       0x1a),
 ('LANG_SINDHI',        0x59),
 ('LANG_SLOVAK',        0x1b),
 ('LANG_SLOVENIAN',     0x24),
 ('LANG_SPANISH',       0x0a),
 ('LANG_SWAHILI',       0x41),
 ('LANG_SWEDISH',       0x1d),
 ('LANG_SYRIAC',        0x5a),
 ('LANG_TAMIL',         0x49),
 ('LANG_TATAR',         0x44),
 ('LANG_TELUGU',        0x4a),
 ('LANG_THAI',          0x1e),
 ('LANG_TURKISH',       0x1f),
 ('LANG_UKRAINIAN',     0x22),
 ('LANG_URDU',          0x20),
 ('LANG_UZBEK',         0x43),
 ('LANG_VIETNAMESE',    0x2a),
 ('LANG_GAELIC',        0x3c),
 ('LANG_MALTESE',       0x3a),
 ('LANG_MAORI',         0x28),
 ('LANG_RHAETO_ROMANCE',0x17),
 ('LANG_SAAMI',         0x3b),
 ('LANG_SORBIAN',       0x2e),
 ('LANG_SUTU',          0x30),
 ('LANG_TSONGA',        0x31),
 ('LANG_TSWANA',        0x32),
 ('LANG_VENDA',         0x33),
 ('LANG_XHOSA',         0x34),
 ('LANG_ZULU',          0x35),
 ('LANG_ESPERANTO',     0x8f),
 ('LANG_WALON',         0x90),
 ('LANG_CORNISH',       0x91),
 ('LANG_WELSH',         0x92),
 ('LANG_BRETON',        0x93) ]

LANG = dict(lang+[(e[1], e[0]) for e in lang])


# Sublanguage definitions
sublang =  [
 ('SUBLANG_NEUTRAL',                        0x00),
 ('SUBLANG_DEFAULT',                        0x01),
 ('SUBLANG_SYS_DEFAULT',                    0x02),
 ('SUBLANG_ARABIC_SAUDI_ARABIA',            0x01),
 ('SUBLANG_ARABIC_IRAQ',                    0x02),
 ('SUBLANG_ARABIC_EGYPT',                   0x03),
 ('SUBLANG_ARABIC_LIBYA',                   0x04),
 ('SUBLANG_ARABIC_ALGERIA',                 0x05),
 ('SUBLANG_ARABIC_MOROCCO',                 0x06),
 ('SUBLANG_ARABIC_TUNISIA',                 0x07),
 ('SUBLANG_ARABIC_OMAN',                    0x08),
 ('SUBLANG_ARABIC_YEMEN',                   0x09),
 ('SUBLANG_ARABIC_SYRIA',                   0x0a),
 ('SUBLANG_ARABIC_JORDAN',                  0x0b),
 ('SUBLANG_ARABIC_LEBANON',                 0x0c),
 ('SUBLANG_ARABIC_KUWAIT',                  0x0d),
 ('SUBLANG_ARABIC_UAE',                     0x0e),
 ('SUBLANG_ARABIC_BAHRAIN',                 0x0f),
 ('SUBLANG_ARABIC_QATAR',                   0x10),
 ('SUBLANG_AZERI_LATIN',                    0x01),
 ('SUBLANG_AZERI_CYRILLIC',                 0x02),
 ('SUBLANG_CHINESE_TRADITIONAL',            0x01),
 ('SUBLANG_CHINESE_SIMPLIFIED',             0x02),
 ('SUBLANG_CHINESE_HONGKONG',               0x03),
 ('SUBLANG_CHINESE_SINGAPORE',              0x04),
 ('SUBLANG_CHINESE_MACAU',                  0x05),
 ('SUBLANG_DUTCH',                          0x01),
 ('SUBLANG_DUTCH_BELGIAN',                  0x02),
 ('SUBLANG_ENGLISH_US',                     0x01),
 ('SUBLANG_ENGLISH_UK',                     0x02),
 ('SUBLANG_ENGLISH_AUS',                    0x03),
 ('SUBLANG_ENGLISH_CAN',                    0x04),
 ('SUBLANG_ENGLISH_NZ',                     0x05),
 ('SUBLANG_ENGLISH_EIRE',                   0x06),
 ('SUBLANG_ENGLISH_SOUTH_AFRICA',           0x07),
 ('SUBLANG_ENGLISH_JAMAICA',                0x08),
 ('SUBLANG_ENGLISH_CARIBBEAN',              0x09),
 ('SUBLANG_ENGLISH_BELIZE',                 0x0a),
 ('SUBLANG_ENGLISH_TRINIDAD',               0x0b),
 ('SUBLANG_ENGLISH_ZIMBABWE',               0x0c),
 ('SUBLANG_ENGLISH_PHILIPPINES',            0x0d),
 ('SUBLANG_FRENCH',                         0x01),
 ('SUBLANG_FRENCH_BELGIAN',                 0x02),
 ('SUBLANG_FRENCH_CANADIAN',                0x03),
 ('SUBLANG_FRENCH_SWISS',                   0x04),
 ('SUBLANG_FRENCH_LUXEMBOURG',              0x05),
 ('SUBLANG_FRENCH_MONACO',                  0x06),
 ('SUBLANG_GERMAN',                         0x01),
 ('SUBLANG_GERMAN_SWISS',                   0x02),
 ('SUBLANG_GERMAN_AUSTRIAN',                0x03),
 ('SUBLANG_GERMAN_LUXEMBOURG',              0x04),
 ('SUBLANG_GERMAN_LIECHTENSTEIN',           0x05),
 ('SUBLANG_ITALIAN',                        0x01),
 ('SUBLANG_ITALIAN_SWISS',                  0x02),
 ('SUBLANG_KASHMIRI_SASIA',                 0x02),
 ('SUBLANG_KASHMIRI_INDIA',                 0x02),
 ('SUBLANG_KOREAN',                         0x01),
 ('SUBLANG_LITHUANIAN',                     0x01),
 ('SUBLANG_MALAY_MALAYSIA',                 0x01),
 ('SUBLANG_MALAY_BRUNEI_DARUSSALAM',        0x02),
 ('SUBLANG_NEPALI_INDIA',                   0x02),
 ('SUBLANG_NORWEGIAN_BOKMAL',               0x01),
 ('SUBLANG_NORWEGIAN_NYNORSK',              0x02),
 ('SUBLANG_PORTUGUESE',                     0x02),
 ('SUBLANG_PORTUGUESE_BRAZILIAN',           0x01),
 ('SUBLANG_SERBIAN_LATIN',                  0x02),
 ('SUBLANG_SERBIAN_CYRILLIC',               0x03),
 ('SUBLANG_SPANISH',                        0x01),
 ('SUBLANG_SPANISH_MEXICAN',                0x02),
 ('SUBLANG_SPANISH_MODERN',                 0x03),
 ('SUBLANG_SPANISH_GUATEMALA',              0x04),
 ('SUBLANG_SPANISH_COSTA_RICA',             0x05),
 ('SUBLANG_SPANISH_PANAMA',                 0x06),
 ('SUBLANG_SPANISH_DOMINICAN_REPUBLIC',     0x07),
 ('SUBLANG_SPANISH_VENEZUELA',              0x08),
 ('SUBLANG_SPANISH_COLOMBIA',               0x09),
 ('SUBLANG_SPANISH_PERU',                   0x0a),
 ('SUBLANG_SPANISH_ARGENTINA',              0x0b),
 ('SUBLANG_SPANISH_ECUADOR',                0x0c),
 ('SUBLANG_SPANISH_CHILE',                  0x0d),
 ('SUBLANG_SPANISH_URUGUAY',                0x0e),
 ('SUBLANG_SPANISH_PARAGUAY',               0x0f),
 ('SUBLANG_SPANISH_BOLIVIA',                0x10),
 ('SUBLANG_SPANISH_EL_SALVADOR',            0x11),
 ('SUBLANG_SPANISH_HONDURAS',               0x12),
 ('SUBLANG_SPANISH_NICARAGUA',              0x13),
 ('SUBLANG_SPANISH_PUERTO_RICO',            0x14),
 ('SUBLANG_SWEDISH',                        0x01),
 ('SUBLANG_SWEDISH_FINLAND',                0x02),
 ('SUBLANG_URDU_PAKISTAN',                  0x01),
 ('SUBLANG_URDU_INDIA',                     0x02),
 ('SUBLANG_UZBEK_LATIN',                    0x01),
 ('SUBLANG_UZBEK_CYRILLIC',                 0x02),
 ('SUBLANG_DUTCH_SURINAM',                  0x03),
 ('SUBLANG_ROMANIAN',                       0x01),
 ('SUBLANG_ROMANIAN_MOLDAVIA',              0x02),
 ('SUBLANG_RUSSIAN',                        0x01),
 ('SUBLANG_RUSSIAN_MOLDAVIA',               0x02),
 ('SUBLANG_CROATIAN',                       0x01),
 ('SUBLANG_LITHUANIAN_CLASSIC',             0x02),
 ('SUBLANG_GAELIC',                         0x01),
 ('SUBLANG_GAELIC_SCOTTISH',                0x02),
 ('SUBLANG_GAELIC_MANX',                    0x03) ]

SUBLANG = dict(sublang+[(e[1], e[0]) for e in sublang])


class PEFormatError(Exception):
    """Generic PE format error exception."""
    
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Dump:
    """Convenience class for dumping the PE information."""
    
    def __init__(self):
        self.text = ''
    
        
    def add_lines(self, txt, indent=0):
        """Adds a list of lines.
        
        The list can be indented with the optional argument 'indent'.
        """
        for line in txt:
            self.add_line(line, indent)
        
            
    def add_line(self, txt, indent=0):
        """Adds a line.
        
        The line can be indented with the optional argument 'indent'.
        """
        
        self.add(txt+'\n', indent)
    
        
    def add(self, txt, indent=0):
        """Adds some text, no newline will be appended.
        
        The text can be indented with the optional argument 'indent'.
        """
        
        if isinstance(txt, unicode):
            s = []
            for c in txt:
                try:
                    s.append(str(c))
                except UnicodeEncodeError, e:
                    s.append(repr(c))
            txt = ''.join(s)
        
        self.text += ' '*indent+txt
    
        
    def add_header(self, txt):
        """Adds a header element."""
        
        self.add_line('-'*10+txt+'-'*10+'\n')
        
        
    def add_newline(self):
        """Adds a newline."""
        
        self.text += '\n'
        
        
    def get_text(self):
        """Get the text in its current state."""
    
        return self.text



class Structure:
    """Prepare structure object to extract members from data.
    
    Format is a list containing definitions for the elements
    of the structure.
    """
    
    
    def __init__(self, format, name=None, file_offset=None):
        # Format is forced little endian, for big endian non Intel platforms
        self.__format__ = '<'
        self.__keys__ = []
#        self.values = {}
        self.__format_length__ = 0
        self.__set_format__(format[1])
        self._all_zeroes = False
        self.__unpacked_data_elms__ = None
        self.__file_offset__ = file_offset
        if name:
            self.name = name
        else:
            self.name = format[0]
                
            
    def __get_format__(self):
        return self.__format__
        
        
    def get_file_offset(self):
        return self.__file_offset__

    def set_file_offset(self, offset):
        self.__file_offset__ = offset
        
    def all_zeroes(self):
        """Returns true is the unpacked data is all zeroes."""
        
        return self._all_zeroes

                
    def __set_format__(self, format):
    
        for elm in format:
            if ',' in elm:
                elm_type, elm_name = elm.split(',', 1)
                self.__format__ += elm_type
                
                elm_names = elm_name.split(',')
                names = []
                for elm_name in elm_names:
                    if elm_name in self.__keys__:
                        search_list = [x[:len(elm_name)] for x in self.__keys__]
                        occ_count = search_list.count(elm_name)
                        elm_name = elm_name+'_'+str(occ_count)
                    names.append(elm_name)
                # Some PE header structures have unions on them, so a certain
                # value might have different names, so each key has a list of
                # all the possible members referring to the data.
                self.__keys__.append(names)
                    
        self.__format_length__ = struct.calcsize(self.__format__)
        
        
    def sizeof(self):
        """Return size of the structure."""
    
        return self.__format_length__
        
        
    def __unpack__(self, data):
    
        if len(data)>self.__format_length__:
            data = data[:self.__format_length__]
            
        # OC Patch:
        # Some malware have incorrect header lengths.
        # Fail gracefully if this occurs
        # Buggy malware: a29b0118af8b7408444df81701ad5a7f
        #
        elif len(data)<self.__format_length__:
            raise PEFormatError('Data length less than expected header length.')

            
        if data.count(chr(0)) == len(data):
            self._all_zeroes = True
            
        self.__unpacked_data_elms__ = struct.unpack(self.__format__, data)
        for i in range(len(self.__unpacked_data_elms__)):
            for key in self.__keys__[i]:
#                self.values[key] = self.__unpacked_data_elms__[i]
                setattr(self, key, self.__unpacked_data_elms__[i])


    def __pack__(self):
    
        new_values = []
        
        for i in range(len(self.__unpacked_data_elms__)):
        
            for key in self.__keys__[i]:
                new_val = getattr(self, key)
                old_val = self.__unpacked_data_elms__[i]
                
                # In the case of Unions, when the first changed value
                # is picked the loop is exited
                if new_val != old_val:
                    break
                
            new_values.append(new_val)
            
        return struct.pack(self.__format__, *new_values)
        
                

    def dump(self, indentation=0):
        """Returns a string representation of the structure."""
    
        dump = []
        
        dump.append('[%s]' % self.name)

        # Refer to the __set_format__ method for an explanation
        # of the following construct.
        for keys in self.__keys__:
            for key in keys:

                val = getattr(self, key)
                if isinstance(val, int) or isinstance(val, long):
                    val_str = '%-8X' % (val)
                    if key == 'TimeDateStamp' or key == 'dwTimeStamp':
                        try:
                            val_str += ' [%s]' % time.ctime(val)
                        except exceptions.ValueError, e:
                            val_str += ' [INVALID TIME]'
                else:
                    val_str = ''.join(filter(lambda c:c != '\0', str(val)))

                dump.append('%-30s %s' % (key+':', val_str))

        return dump



class SectionStructure(Structure):
    """Convenience section handling class."""

    def get_data(self, start, length=None):
        """Get data chunk from a section.
        
        Allows to query data from the section by passing the
        addresses where the PE file would be loaded by default.
        It is then possible to retrieve code and data by its real
        addresses as it would be if loaded.
        """

        end = None
        offset = start - self.VirtualAddress

        if length:
            end = offset+length

        return self.data[offset:end]

    def get_offset_from_rva(self, rva):
        return (rva - self.VirtualAddress) + self.PointerToRawData

    def contains(self, address):
        """Check whether the section contains the address provided."""

        return address>=self.VirtualAddress and address<self.VirtualAddress+len(self.data)



class DataContainer:
    """Generic data container."""
	
    def __init__(self, **args):
        for key, value in args.items():
            setattr(self, key, value)


class ImportDescData(DataContainer):
    """Holds import descriptor information.
    
    dll:        name of the imported DLL
    imports:    list of imported symbols (ImportData instances)
    struct:     IMAGE_IMPORT_DESCRIPTOR sctruture
    """

class ImportData(DataContainer):
    """Holds imported symbol's information.
    
    ordinal:    Ordinal of the symbol
    name:       Name of the symbol
    bound:      If the symbol is bound, this contains
                the address.
    """
    
class ExportDirData(DataContainer):
    """Holds export directory information.
                    
    struct:     IMAGE_EXPORT_DIRECTORY structure
    symbols:    list of exported symbols (ExportData instances)
"""
    
class ExportData(DataContainer):
    """Holds exported symbols' information.
    
    ordinal:    ordinal of the symbol
    address:    address of the symbol
    name:       name of the symbol (None if the symbol is
                exported by ordinal only)
    forwarder:  if the symbol is forwarded it will
                contain the name of the target symbol,
                None otherwise.
    """
              

class ResourceDirData(DataContainer):
    """Holds resource directory information.
    
    struct:     IMAGE_RESOURCE_DIRECTORY structure
    entries:    list of entries (ResourceDirEntryData instances)
    """
    
class ResourceDirEntryData(DataContainer):
    """Holds resource directory entry data.
    
    struct:     IMAGE_RESOURCE_DIRECTORY_ENTRY structure
    name:       If the resource is identified by name this
                attribute will contain the name string. None
                otherwise. If identified by id, the id is
                availabe at 'struct.Id'
    id:         the id, also in struct.Id
    directory:  If this entry has a lower level directory
                this attribute will point to the
                ResourceDirData instance representing it.
    data:       If this entry has no futher lower directories
                and points to the actual resource data, this
                attribute will reference the corresponding
                ResourceDataEntryData instance.
    (Either of the 'directory' or 'data' attribute will exist,
    but not both.)
    """

class ResourceDataEntryData(DataContainer):
    """Holds resource data entry information.
    
    struct:     IMAGE_RESOURCE_DATA_ENTRY structure
    lang:       Primary language ID
    sublang:    Sublanguage ID
    """

class DebugData(DataContainer):
    """Holds debug information.
    
    struct:     IMAGE_DEBUG_DIRECTORY structure
    """

class BaseRelocationData(DataContainer):
    """Holds base relocation information.
    
    struct:     IMAGE_BASE_RELOCATION structure
    entries:    list of relocation data (RelocationData instances)
    """
    
class RelocationData(DataContainer):
    """Holds relocation information.
    
    type:       Type of relocation
                The type string is can be obtained by
                RELOCATION_TYPE[type]
    rva:        RVA of the relocation
    """

class TlsData(DataContainer):
    """Holds TLS information.
    
    struct:     IMAGE_TLS_DIRECTORY structure
    """

class BoundImportDescData(DataContainer):
    """Holds bound import descriptor data.
    
    This directory entry will provide with information on the
    DLLs this PE files has been bound to (if bound at all).
    The structure will contain the name and timestamp of the
    DLL at the time of binding so that the loader can know
    whether it differs from the one currently present in the
    system and must, therefore, re-bind the PE's imports.
    
    struct:     IMAGE_BOUND_IMPORT_DESCRIPTOR structure
    name:       DLL name
    entries:    list of entries (BoundImportRefData instances)
                the entries will exist if this DLL has forwarded
                symbols. If so, the destination DLL will have an
                entry in this list.
    """

class BoundImportRefData(DataContainer):
    """Holds bound import forwader reference data.
    
    Contains the same information as the bound descriptor but
    for forwarded DLLs, if any.
    
    struct:     IMAGE_BOUND_FORWARDER_REF structure
    name:       dll name
    """


class PE:
    """A Portable Executable representation.
    
    This class provides access to most of the information in a PE file.
    
    It expects to be supplied the name of the file to load or PE data
    to process and an optional argument 'fast_load' (False by default)
    which controls whether to load all the directories information,
    which can be quite time consuming.
    
    pe = pefile.PE('module.dll')
    pe = pefile.PE(name='module.dll')
    
    would load 'module.dll' and process it. If the data would be already
    available in a buffer the same could be achieved with:
    
    pe = pefile.PE(data=module_dll_data)
    
    The "fast_load" can be set to a default by setting its value in the
    module itself by means,for instance, of a "pefile.fast_load = True".
    That will make all the subsequent instances not to load the
    whole PE structure. The "full_load" method can be used to parse
    the missing data at a later stage.
    
    Basic headers information will be available in the attributes:
    
    DOS_HEADER
    NT_HEADERS
    FILE_HEADER
    OPTIONAL_HEADER
    
    All of them will contain among their attrbitues the members of the
    corresponding structures as defined in WINNT.H
    
    The raw data corresponding to the header (from the beginning of the
    file up to the start of the first section) will be avaiable in the
    instance's attribute 'header' as a string.
    
    The sections will be available as a list in the 'sections' attribute.
    Each entry will contain as attributes all the structure's members.
    
    Directory entries will be available as attributes (if they exist):
    (no other entries are processed at this point)
    
    DIRECTORY_ENTRY_IMPORT (list of ImportDescData instances)
    DIRECTORY_ENTRY_EXPORT (ExportDirData instance)
    DIRECTORY_ENTRY_RESOURCE (ResourceDirData instance)
    DIRECTORY_ENTRY_DEBUG (list of DebugData instances)
    DIRECTORY_ENTRY_BASERELOC (list of BaseRelocationData instances)
    DIRECTORY_ENTRY_TLS 
    DIRECTORY_ENTRY_BOUND_IMPORT (list of BoundImportData instances)
    
    The following dictionary attributes provide ways of mapping different
    constants. They will accept the numeric value and return the string
    representation and the opposite, feed in the string and get the
    numeric constant:
    
    DIRECTORY_ENTRY
    IMAGE_CHARACTERISTICS
    SECTION_CHARACTERISTICS
    DEBUG_TYPE
    SUBSYSTEM_TYPE
    MACHINE_TYPE
    RELOCATION_TYPE
    RESOURCE_TYPE
    LANG
    SUBLANG
    """

    #
    # Format specifications for PE structures.
    #
    
    __IMAGE_DOS_HEADER_format__ = ('IMAGE_DOS_HEADER',
        ('H,e_magic', 'H,e_cblp', 'H,e_cp',
        'H,e_crlc', 'H,e_cparhdr', 'H,e_minalloc',
        'H,e_maxalloc', 'H,e_ss', 'H,e_sp', 'H,e_csum',
        'H,e_ip', 'H,e_cs', 'H,e_lfarlc', 'H,e_ovno', '8s,e_res',
        'H,e_oemid', 'H,e_oeminfo', '20s,e_res2',
        'L,e_lfanew'))
        
    __IMAGE_FILE_HEADER_format__ = ('IMAGE_FILE_HEADER',
        ('H,Machine', 'H,NumberOfSections',
        'L,TimeDateStamp', 'L,PointerToSymbolTable',
        'L,NumberOfSymbols', 'H,SizeOfOptionalHeader',
        'H,Characteristics'))
        
    __IMAGE_DATA_DIRECTORY_format__ = ('IMAGE_DATA_DIRECTORY',
        ('L,VirtualAddress', 'L,Size'))
    
    __IMAGE_OPTIONAL_HEADER_format__ = ('IMAGE_OPTIONAL_HEADER',
        ('H,Magic', 'B,MajorLinkerVersion',
        'B,MinorLinkerVersion', 'L,SizeOfCode',
        'L,SizeOfInitializedData', 'L,SizeOfUninitializedData',
        'L,AddressOfEntryPoint', 'L,BaseOfCode', 'L,BaseOfData',
        'L,ImageBase', 'L,SectionAlignment', 'L,FileAlignment',
        'H,MajorOperatingSystemVersion', 'H,MinorOperatingSystemVersion',
        'H,MajorImageVersion', 'H,MinorImageVersion',
        'H,MajorSubsystemVersion', 'H,MinorSubsystemVersion',
        'L,Reserved1', 'L,SizeOfImage', 'L,SizeOfHeaders',
        'L,CheckSum', 'H,Subsystem', 'H,DllCharacteristics',
        'L,SizeOfStackReserve', 'L,SizeOfStackCommit',
        'L,SizeOfHeapReserve', 'L,SizeOfHeapCommit',
        'L,LoaderFlags', 'L,NumberOfRvaAndSizes' ))


    __IMAGE_OPTIONAL_HEADER64_format__ = ('IMAGE_OPTIONAL_HEADER64',
        ('H,Magic', 'B,MajorLinkerVersion',
        'B,MinorLinkerVersion', 'L,SizeOfCode',
        'L,SizeOfInitializedData', 'L,SizeOfUninitializedData',
        'L,AddressOfEntryPoint', 'L,BaseOfCode',
        'Q,ImageBase', 'L,SectionAlignment', 'L,FileAlignment',
        'H,MajorOperatingSystemVersion', 'H,MinorOperatingSystemVersion',
        'H,MajorImageVersion', 'H,MinorImageVersion',
        'H,MajorSubsystemVersion', 'H,MinorSubsystemVersion',
        'L,Reserved1', 'L,SizeOfImage', 'L,SizeOfHeaders',
        'L,CheckSum', 'H,Subsystem', 'H,DllCharacteristics',
        'Q,SizeOfStackReserve', 'Q,SizeOfStackCommit',
        'Q,SizeOfHeapReserve', 'Q,SizeOfHeapCommit',
        'L,LoaderFlags', 'L,NumberOfRvaAndSizes' ))
        
        
    __IMAGE_NT_HEADERS_format__ = ('IMAGE_NT_HEADERS', ('L,Signature',))
        
    __IMAGE_SECTION_HEADER_format__ = ('IMAGE_SECTION_HEADER',
        ('8s,Name', 'L,Misc,Misc_PhysicalAddress,Misc_VirtualSize',
        'L,VirtualAddress', 'L,SizeOfRawData', 'L,PointerToRawData',
        'L,PointerToRelocations', 'L,PointerToLinenumbers',
        'H,NumberOfRelocations', 'H,NumberOfLinenumbers',
        'L,Characteristics'))

    __IMAGE_DELAY_IMPORT_DESCRIPTOR_format__ = ('IMAGE_DELAY_IMPORT_DESCRIPTOR',
        ('L,grAttrs', 'L,szName', 'L,phmod', 'L,pIAT', 'L,pINT',
        'L,pBoundIAT', 'L,pUnloadIAT', 'L,dwTimeStamp'))

    __IMAGE_IMPORT_DESCRIPTOR_format__ =  ('IMAGE_IMPORT_DESCRIPTOR',
        ('L,OriginalFirstThunk,Characteristics',
        'L,TimeDateStamp', 'L,ForwarderChain', 'L,Name', 'L,FirstThunk'))

    __IMAGE_EXPORT_DIRECTORY_format__ =  ('IMAGE_EXPORT_DIRECTORY',
        ('L,Characteristics',
        'L,TimeDateStamp', 'H,MajorVersion', 'H,MinorVersion', 'L,Name',
        'L,Base', 'L,NumberOfFunctions', 'L,NumberOfNames',
        'L,AddressOfFunctions', 'L,AddressOfNames', 'L,AddressOfNameOrdinals'))

    __IMAGE_RESOURCE_DIRECTORY_format__ = ('IMAGE_RESOURCE_DIRECTORY',
        ('L,Characteristics',
        'L,TimeDateStamp', 'H,MajorVersion', 'H,MinorVersion',
        'H,NumberOfNamedEntries', 'H,NumberOfIdEntries'))

    __IMAGE_RESOURCE_DIRECTORY_ENTRY_format__ = ('IMAGE_RESOURCE_DIRECTORY_ENTRY',
        ('L,Name',
        'L,OffsetToData'))
            
    __IMAGE_RESOURCE_DATA_ENTRY_format__ = ('IMAGE_RESOURCE_DATA_ENTRY',
        ('L,OffsetToData', 'L,Size', 'L,CodePage', 'L,Reserved'))
    
    __IMAGE_THUNK_DATA_format__ = ('IMAGE_THUNK_DATA',
        ('L,ForwarderString,Function,Ordinal,AddressOfData',))

    __IMAGE_THUNK_DATA64_format__ = ('IMAGE_THUNK_DATA',
        ('Q,ForwarderString,Function,Ordinal,AddressOfData',))

    __IMAGE_DEBUG_DIRECTORY_format__ = ('IMAGE_DEBUG_DIRECTORY',
        ('L,Characteristics', 'L,TimeDateStamp', 'H,MajorVersion',
        'H,MinorVersion', 'L,Type', 'L,SizeOfData', 'L,AddressOfRawData',
        'L,PointerToRawData'))
    
    __IMAGE_BASE_RELOCATION_format__ = ('IMAGE_BASE_RELOCATION',
        ('L,VirtualAddress', 'L,SizeOfBlock') )

    __IMAGE_TLS_DIRECTORY_format__ = ('IMAGE_TLS_DIRECTORY',
        ('L,StartAddressOfRawData', 'L,EndAddressOfRawData',
        'L,AddressOfIndex', 'L,AddressOfCallBacks',
        'L,SizeOfZeroFill', 'L,Characteristics' ) )

    __IMAGE_TLS_DIRECTORY64_format__ = ('IMAGE_TLS_DIRECTORY',
        ('Q,StartAddressOfRawData', 'Q,EndAddressOfRawData',
        'Q,AddressOfIndex', 'Q,AddressOfCallBacks',
        'L,SizeOfZeroFill', 'L,Characteristics' ) )

    __IMAGE_BOUND_IMPORT_DESCRIPTOR_format__ = ('IMAGE_BOUND_IMPORT_DESCRIPTOR',
        ('L,TimeDateStamp', 'H,OffsetModuleName', 'H,NumberOfModuleForwarderRefs'))

    __IMAGE_BOUND_FORWARDER_REF_format__ = ('IMAGE_BOUND_FORWARDER_REF',
        ('L,TimeDateStamp', 'H,OffsetModuleName', 'H,Reserved') )


    def __init__(self, name=None, data=None, fast_load=None):
    
        self.sections = []
        
        self.PE_TYPE = None
        
        if  not name and not data:
            return
            
        # This list will keep track of all the structures created.
        # That will allow for an easy iteration through the list
        # in order to save the modifications made
        self.__structures__ = []

        if not fast_load:
            fast_load = globals()['fast_load']
        self.__parse__(name, data, fast_load)
                    
        
    
    def __unpack_data__(self, format, data, file_offset):
        """Apply structure format to raw data.
        
        Returns and unpacked structure object if successful, None otherwise.
        """
    
        structure = Structure(format, file_offset=file_offset)
        if len(data) < structure.sizeof():
            return None
    
        structure.__unpack__(data)
        self.__structures__.append(structure)
    
        return structure
        

        
    def __parse__(self, fname, data, fast_load):
        """Parse a Portable Executable file.
        
        Loads a PE file, parsing all its structures and making them available
        through the instance's attributes.
        """
        
        if fname:
            fd = file(fname, 'rb')
            self.__data__ = fd.read()
            fd.close()
        elif data:
            self.__data__ = data
        

        self.DOS_HEADER = self.__unpack_data__(
            self.__IMAGE_DOS_HEADER_format__,
            self.__data__, file_offset=0)
            
        if not self.DOS_HEADER or self.DOS_HEADER.e_magic != IMAGE_DOS_SIGNATURE:
            raise PEFormatError('DOS Header magic not found.')

        # OC Patch:
        # Check for sane value in e_lfanew
        #                
        if self.DOS_HEADER.e_lfanew > len(self.__data__):
            raise PEFormatError('Invalid e_lfanew value, probably not a PE file')

        nt_headers_offset = self.DOS_HEADER.e_lfanew

        self.NT_HEADERS = self.__unpack_data__(
            self.__IMAGE_NT_HEADERS_format__,
            self.__data__[nt_headers_offset:],
            file_offset = nt_headers_offset)

        # We better check the signature right here, before the file screws
        # around with sections:
        # OC Patch:
        # Some malware will cause the Signature value to not exist at all
        if not self.NT_HEADERS or not self.NT_HEADERS.Signature:
            raise PEFormatError('NT Headers not found.')

        if self.NT_HEADERS.Signature != IMAGE_NT_SIGNATURE:
            raise PEFormatError('Invalid NT Headers signature.')
                
        self.FILE_HEADER = self.__unpack_data__(
            self.__IMAGE_FILE_HEADER_format__,
            self.__data__[nt_headers_offset+4:],
            file_offset = nt_headers_offset+4)
        image_flags = self.retrieve_flags(IMAGE_CHARACTERISTICS, 'IMAGE_FILE_')
        
        if not self.FILE_HEADER:
            raise PEFormatError('File Header missing')

        # Set the image's flags according the the Characteristics member
        self.set_flags(self.FILE_HEADER, self.FILE_HEADER.Characteristics, image_flags)
        
        optional_header_offset =    \
            nt_headers_offset+4+self.FILE_HEADER.sizeof()

        # Note: location of sections can be controlled from PE header:
        sections_offset = optional_header_offset + self.FILE_HEADER.SizeOfOptionalHeader

        self.OPTIONAL_HEADER = self.__unpack_data__(
            self.__IMAGE_OPTIONAL_HEADER_format__,
            self.__data__[optional_header_offset:],
            file_offset = optional_header_offset)
         
            
        # Check the Magic in the OPTIONAL_HEADER and set the PE file
        # type accordingly
        #
        if self.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE:
        
            self.PE_TYPE = OPTIONAL_HEADER_MAGIC_PE
            
        elif self.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE_PLUS:

            self.PE_TYPE = OPTIONAL_HEADER_MAGIC_PE_PLUS
        
            self.OPTIONAL_HEADER = self.__unpack_data__(
                self.__IMAGE_OPTIONAL_HEADER64_format__,
                self.__data__[optional_header_offset:],
                file_offset = optional_header_offset)
        
        # OC Patch:
        # Die gracefully if there is no OPTIONAL_HEADER field
        # 975440f5ad5e2e4a92c4d9a5f22f75c1
        if self.PE_TYPE is None or not self.OPTIONAL_HEADER:
            raise PEFormatError("No Optional Header found, invalid PE32 or PE32+ file")
            

        self.OPTIONAL_HEADER.DATA_DIRECTORY = []
        offset = (optional_header_offset + self.OPTIONAL_HEADER.sizeof())
            
        
        self.NT_HEADERS.FILE_HEADER = self.FILE_HEADER
        self.NT_HEADERS.OPTIONAL_HEADER = self.OPTIONAL_HEADER
            

        for i in xrange(self.OPTIONAL_HEADER.NumberOfRvaAndSizes):
            dir_entry = self.__unpack_data__(
                self.__IMAGE_DATA_DIRECTORY_format__,
                self.__data__[offset:],
                file_offset = offset)
            # Would fail if missing an entry
            # 1d4937b2fa4d84ad1bce0309857e70ca offending sample
            try:
                dir_entry.name = DIRECTORY_ENTRY[i]
            except KeyError:
                break
                
            offset += dir_entry.sizeof()
            
            self.OPTIONAL_HEADER.DATA_DIRECTORY.append(dir_entry)

            # If the offset goes outside the optional header,
            # the loop is broken, regardless of how many directories
            # NumberOfRvaAndSizes says there are
            #
            if offset >= (optional_header_offset + 
                self.FILE_HEADER.SizeOfOptionalHeader) :
                
                break
                
                        
        offset = self.parse_sections(sections_offset)
        
        # OC Patch:
        # There could be a problem if there are no raw data sections
        # greater than 0
        # fc91013eb72529da005110a3403541b6 example
        # Should this throw an exception in the minimum header offset
        # can't be found?
        #
        rawDataPointers = [
            s.PointerToRawData for s in self.sections if s.PointerToRawData>0]
            
        if len(rawDataPointers) > 0:
            lowest_section_offset = min(rawDataPointers)
        else:
            lowest_section_offset = None

        if not lowest_section_offset or lowest_section_offset<offset:
            self.header = self.__data__[:offset]
        else:
            self.header = self.__data__[:lowest_section_offset]
        
        if not fast_load:
            self.parse_data_directories()


    def full_load(self):
        """Process the data directories.
        
        This mathod will load the data directories which might not have
        been loaded if the "fast_load" option was used.
        """
        
        self.parse_data_directories()
        
        
    def write(self, filename=None):
        """Write the PE file.
        
        This function will process all headers and components
        of the PE file and include all changes made (by just
        assigning to attributes in the PE objects) and write
        the changes back to a file whose name is provided as
        an argument. The filename is optional.
        The data to be written to the file will be returned
        as a 'str' object.
        """
    
        file_data = list(self.__data__)
        for struct in self.__structures__:
        
            struct_data = list(struct.__pack__())
            offset = struct.get_file_offset()
            
            file_data[offset:offset+len(struct_data)] = struct_data
            
        new_file_data = ''.join(file_data)
        if filename:
            f = file(filename, 'w+')
            f.write(new_file_data)
            f.close()

        return new_file_data
        

                
    def parse_sections(self, offset):
        """Fetch the PE file sections.
        
        The sections will be readily available in the "sections" attribute.
        Its attributes will contain all the section information plus "data"
        a buffer containing the section's data.
        
        The "Characteristics" member will be processed and attributes 
        representing the section characteristics (with the 'IMAGE_SCN_'
        string trimmed from the constant's names) will be added to the
        section instance.
        
        Refer to the SectionStructure class for additional info.
        """
        
        self.sections = []
        
        for i in range(self.FILE_HEADER.NumberOfSections):
            section = SectionStructure(self.__IMAGE_SECTION_HEADER_format__)
            section_offset = offset + section.sizeof()*i
            section.set_file_offset(section_offset)
            section.__unpack__(self.__data__[section_offset:])
            self.__structures__.append(section)
            
            # If the string contains a 0 byte terminating it, it's
            # truncated to that length. otherwise all data is kept
            #
            end_of_str = section.Name.find('\0')
            if end_of_str >= 0:
                section.Name = ''.join([c for c in section.Name[:end_of_str]])
            
            #
            # Some packer used a non-aligned PointerToRawData in the sections,
            # which causes several common tools not to load the section data
            # properly as they blindly read from the indicated offset.
            # It seems that Windows will round the offset down to the largest
            # offset multiple of FileAlignment which is smaller than
            # PointerToRawData. The following code will do the same.
            #
            
            alignment = self.OPTIONAL_HEADER.FileAlignment
            section_data_start = section.PointerToRawData
            section_data_start = int(section_data_start/alignment)*alignment
            
            section_data_end = section_data_start+section.SizeOfRawData
            section.data = self.__data__[section_data_start:section_data_end]
            
            section_flags = self.retrieve_flags(SECTION_CHARACTERISTICS, 'IMAGE_SCN_')
            
            # Set the section's flags according the the Characteristics member
            self.set_flags(section, section.Characteristics, section_flags)
            
            self.sections.append(section)
            
        return offset + section.sizeof()*self.FILE_HEADER.NumberOfSections

        
    def retrieve_flags(self, flag_dict, flag_filter):
        """Read the flags from a dictionary and return them in a usable form.
        
        Will return a list of (flag, value) for all flags in "flag_dict"
        matching the filter "flag_filter".
        """
        
        return [(f[0][len(flag_filter):], f[1]) for f in flag_dict.items() if
                isinstance(f[0], str) and f[0].startswith(flag_filter)]

                
    def set_flags(self, obj, flag_field, flags):
        """Will process the flags and set attributes in the object accordingly.
        
        The object "obj" will gain attritutes named after the flags provided in
        "flags" and valued True/False, matching the results of applyin each
        flag value from "flags" to flag_field.
        """
    
        for flag in flags:
            if flag[1] & flag_field:
                setattr(obj, flag[0], True)
            else:
                setattr(obj, flag[0], False)
    
    
            
    def parse_data_directories(self):
        """Parse and process the PE file's data directories."""
        
        directory_parsing = (
            ('IMAGE_DIRECTORY_ENTRY_IMPORT', self.parse_import_directory),
            ('IMAGE_DIRECTORY_ENTRY_EXPORT', self.parse_export_directory),
            ('IMAGE_DIRECTORY_ENTRY_RESOURCE', self.parse_resources_directory),
            ('IMAGE_DIRECTORY_ENTRY_DEBUG', self.parse_debug_directory),
            ('IMAGE_DIRECTORY_ENTRY_BASERELOC', self.parse_relocations_directory),
            ('IMAGE_DIRECTORY_ENTRY_TLS', self.parse_directory_tls),
            ('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT', self.parse_delay_import_directory),
            ('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT', self.parse_directory_bound_imports) )
            
        for entry in directory_parsing:
            # OC Patch:
            #
            try:
                dir_entry = self.OPTIONAL_HEADER.DATA_DIRECTORY[
                    DIRECTORY_ENTRY[entry[0]]]
            except IndexError:
                break
            if dir_entry.VirtualAddress:
                value = entry[1](dir_entry.VirtualAddress, dir_entry.Size)
                if value:
                    setattr(self, entry[0][6:], value)
        
        
    def parse_directory_bound_imports(self, rva, size):
        """"""
        
        bnd_descr = Structure(self.__IMAGE_BOUND_IMPORT_DESCRIPTOR_format__)
        bnd_descr_size = bnd_descr.sizeof()
        start = rva
        
        bound_imports = []
        while True:

            bnd_descr = self.__unpack_data__(
                self.__IMAGE_BOUND_IMPORT_DESCRIPTOR_format__,
                   self.__data__[rva:rva+bnd_descr_size],
                   file_offset = rva)
                   
            if bnd_descr.all_zeroes():
                break
                
            rva += bnd_descr.sizeof()
            
            forwarder_refs = []
            for idx in range(bnd_descr.NumberOfModuleForwarderRefs):
                # Both structures IMAGE_BOUND_IMPORT_DESCRIPTOR and
                # IMAGE_BOUND_FORWARDER_REF have the same size.
                bnd_frwd_ref = self.__unpack_data__(
                    self.__IMAGE_BOUND_FORWARDER_REF_format__,
                    self.__data__[rva:rva+bnd_descr_size],
                    file_offset = rva)
                # OC Patch:
                if not bnd_frwd_ref:
                    raise PEFormatError(
                        "IMAGE_BOUND_FORWARDER_REF cannot be read")
                rva += bnd_frwd_ref.sizeof()
                
                forwarder_refs.append(BoundImportRefData(
                    struct = bnd_frwd_ref,
                    name =  self.get_string_from_data(
                        start+bnd_frwd_ref.OffsetModuleName, self.__data__)))
                
            bound_imports.append(
                BoundImportDescData(
                    struct = bnd_descr,
                    name = self.get_string_from_data(
                        start+bnd_descr.OffsetModuleName, self.__data__),
                    entries = forwarder_refs))
                    
        return bound_imports

        
    def parse_directory_tls(self, rva, size):
        """"""
            
        if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
            format = self.__IMAGE_TLS_DIRECTORY_format__
            
        elif self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
            format = self.__IMAGE_TLS_DIRECTORY64_format__
            
        return TlsData(
            struct = self.__unpack_data__(
                format,
                self.get_data(rva),
                file_offset = self.get_offset_from_rva(rva)) )
    
    
    def parse_relocations_directory(self, rva, size):
        """"""
        
        rlc = Structure(self.__IMAGE_BASE_RELOCATION_format__)
        rlc_size = rlc.sizeof()
        end = rva+size
        
        relocations = []
        while rva<end:
            
            # OC Patch:
            # Malware that has bad rva entries will cause an error.
            # Just continue on after an exception
            #
            try:
                rlc = self.__unpack_data__(
                    self.__IMAGE_BASE_RELOCATION_format__,
                    self.get_data(rva, rlc_size),
                    file_offset = self.get_offset_from_rva(rva) )
            except PEFormatError:
                rlc = None
            
            if not rlc:
                break
                
            reloc_entries = self.parse_relocations(
                rva+rlc_size, rlc.VirtualAddress, rlc.SizeOfBlock-rlc_size)
                
            relocations.append(
                BaseRelocationData(
                    struct = rlc,
                    entries = reloc_entries))
            
            if not rlc.SizeOfBlock:
                break
            rva += rlc.SizeOfBlock
            
        return relocations
    
        
    def parse_relocations(self, data_rva, rva, size):
        """"""
        
        data = self.get_data(data_rva, size)
        
        entries = []
        for idx in range(len(data)/2):
            word = struct.unpack('<H', data[idx*2:(idx+1)*2])[0]
            reloc_type = (word>>12)
            reloc_offset = (word&0x0fff)
            entries.append(
                RelocationData(
                    type = reloc_type,
                    rva = reloc_offset+rva))
            
        return entries

        
    def parse_debug_directory(self, rva, size):
        """"""
            
        dbg = Structure(self.__IMAGE_DEBUG_DIRECTORY_format__)
        dbg_size = dbg.sizeof()
        
        debug = []
        for idx in range(size/dbg_size):
            try:
                data = self.get_data(rva+dbg_size*idx, dbg_size)
            except PEFormatError, e:
                return None
                
            dbg = self.__unpack_data__(
                self.__IMAGE_DEBUG_DIRECTORY_format__,
                data, file_offset = self.get_offset_from_rva(rva+dbg_size*idx))
            debug.append(
                DebugData(
                    struct = dbg))
            
        return debug

                        
    def parse_resources_directory(self, rva, size=0, base_rva = None):
        """Parse the resources directory.
        
        Given the rva of the resources directory, it will process all
        its entries.
        
        The root will have the corresponding member of its structure,
        IMAGE_RESOURCE_DIRECTORY plus 'entries', a list of all the
        entries in the directory.
        
        Those entries will have, correspondingly, all the structure's
        members (IMAGE_RESOURCE_DIRECTORY_ENTRY) and an additional one,
        "directory", pointing to the IMAGE_RESOURCE_DIRECTORY structure
        representing upper layers of the tree. This one will also have
        an 'entries' attribute, pointing to the 3rd, and last, level.
        Another directory with more entries. Those last entries will
        have a new atribute (both 'leaf' or 'data_entry' can be used to
        access it). This structure finally points to the resource data.
        All the members of this structure, IMAGE_RESOURCE_DATA_ENTRY,
        are available as its attributes.
        """
        
        # OC Patch:
        original_rva = rva
        
        if base_rva is None:
            base_rva = rva
        
        resources_section = self.get_section_by_rva(rva)
        
        try:
            # If the RVA is invalid all would blow up. Some EXEs seem to be
            # specially nasty and have an invalid RVA.
            data = self.get_data(rva)
        except PEFormatError, e:
            return None
            
        # Get the resource directory structure, that is, the header
        # of the table preceding the actual entries
        #
        resource_dir = self.__unpack_data__(
            self.__IMAGE_RESOURCE_DIRECTORY_format__, data,
            file_offset = self.get_offset_from_rva(rva) )
        
        dir_entries = []
        
        # Advance the rva to the positon immediately following the directory
        # table header and pointing to the first entry in the table
        #
        rva += resource_dir.sizeof()
        
        number_of_entries = (
            resource_dir.NumberOfNamedEntries +
            resource_dir.NumberOfIdEntries )
        
        
        for idx in range(number_of_entries):
        
            res = self.parse_resource_entry(rva)

            entry_name = None
            entry_id = None
            
            # If all named entries have been processed, only Id ones
            # remain
            
            if idx>=resource_dir.NumberOfNamedEntries:
                entry_id = res.Name
            else:
                entry_name = self.get_string_u_at_rva(base_rva+res.NameOffset)
                
                
            if res.DataIsDirectory:
                # OC Patch:
                #
                # One trick malware can do is to recursively reference
                # the next directory. This causes hilarity to ensue when
                # trying to parse everything correctly.
                # If the original RVA given to this function is equal to
                # the next one to parse, we assume that it's a trick.
                # Instead of raising a PEFormatError this would skip some
                # reasonable data so we just break.
                #
                # 9ee4d0a0caf095314fd7041a3e4404dc is the offending sample
                if original_rva == (base_rva + res.OffsetToDirectory):
                    
                    break
                    
                else:
                    entry_directory = self.parse_resources_directory(
                        base_rva+res.OffsetToDirectory, base_rva=base_rva)

                if not entry_directory:
                    break
                dir_entries.append(
                    ResourceDirEntryData(
                        struct = res,
                        name = entry_name,
                        id = entry_id,
                        directory = entry_directory))
            else:
                entry_data = ResourceDataEntryData(
                    struct = self.parse_resource_data_entry(
                        base_rva + res.OffsetToDirectory),
                    lang = res.Name & 0xff,
                    sublang = (res.Name>>8) & 0xff)
                    
                dir_entries.append(
                    ResourceDirEntryData(
                        struct = res,
                        name = entry_name,
                        id = entry_id,
                        data = entry_data))
                    

            
            rva += res.sizeof()

        return ResourceDirData(
            struct = resource_dir,
            entries = dir_entries)
        
            
    def parse_resource_data_entry(self, rva):
        """Parse a data entry from the resources directory."""
    
        try:
            # If the RVA is invalid all would blow up. Some EXEs seem to be
            # specially nasty and have an invalid RVA.
            data = self.get_data(rva)
        except PEFormatError, e:
            return None
            
        data_entry = self.__unpack_data__(
            self.__IMAGE_RESOURCE_DATA_ENTRY_format__, data,
            file_offset = self.get_offset_from_rva(rva) )
            
        return data_entry

        
    def parse_resource_entry(self, rva):
        """Parse a directory entry from the resources directory."""

        resource = self.__unpack_data__(
            self.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__, self.get_data(rva),
            file_offset = self.get_offset_from_rva(rva) )
            
        #resource.NameIsString = (resource.Name & 0x80000000L) >> 31
        resource.NameOffset = resource.Name & 0x7FFFFFFFL
        
        resource.__pad = resource.Name & 0xFFFF0000L
        resource.Id = resource.Name & 0x0000FFFFL
        
        resource.DataIsDirectory = (resource.OffsetToData & 0x80000000L) >> 31
        resource.OffsetToDirectory = resource.OffsetToData & 0x7FFFFFFFL
        
        return resource
            
                            
    def parse_export_directory(self, rva, size):
        """Parse the export directory.
        
        Given the rva of the export directory, it will process all
        its entries.
        
        The exports will be made available through a list "exports"
        containing a tuple with the following elements:
        
            (ordinal, symbol_address, symbol_name)
            
        And also through a dicionary "exports_by_ordinal" whose keys
        will be the ordinals and the values tuples of the from:
        
            (symbol_address, symbol_name)
            
        The symbol addresses are relative, not absolute.
        """
    
        export_dir =  self.__unpack_data__(
            self.__IMAGE_EXPORT_DIRECTORY_format__, self.get_data(rva),
            file_offset = self.get_offset_from_rva(rva) )
        
        address_of_names = self.get_data(
            export_dir.AddressOfNames, export_dir.NumberOfNames*4)
        address_of_name_ordinals = self.get_data(
            export_dir.AddressOfNameOrdinals, export_dir.NumberOfNames*4)
        address_of_functions = self.get_data(
            export_dir.AddressOfFunctions, export_dir.NumberOfFunctions*4)
            
        exports = []
        
        for i in range(export_dir.NumberOfNames):
        
                
            symbol_name = self.get_string_at_rva(
                self.get_dword_from_data(address_of_names, i))
            
            symbol_ordinal = self.get_word_from_data(
                address_of_name_ordinals, i)
                
            
            if symbol_ordinal*4<len(address_of_functions):
                symbol_address = self.get_dword_from_data(
                    address_of_functions, symbol_ordinal)
            else:
                # Corrupt? a bad pointer... we assume it's all
                # useless, no exports
                return None
            
            # If the funcion's rva points within the export directory
            # it will point to a string with the forwarded symbol's string
            # instead of pointing the the function start address.
            
            if symbol_address>=rva and symbol_address<rva+size:
                forwarder_str = self.get_string_at_rva(symbol_address)
            else:
                forwarder_str = None
        
            
            exports.append(
                ExportData(
                    ordinal = export_dir.Base+symbol_ordinal,
                    address = symbol_address,
                    name = symbol_name,
                    forwarder = forwarder_str))
                    
        ordinals = [exp.ordinal for exp in exports]
        
        for idx in range(export_dir.NumberOfFunctions):

            if not idx+export_dir.Base in ordinals:
                symbol_address = self.get_dword_from_data(
                    address_of_functions, 
                    idx)
                
                #
                # Checking for forwarder again.
                #
                if symbol_address>=rva and symbol_address<rva+size:
                    forwarder_str = self.get_string_at_rva(symbol_address)
                else:
                    forwarder_str = None
                    
                exports.append(
                    ExportData(
                        ordinal = export_dir.Base+idx,
                        address = symbol_address,
                        name = None,
                        forwarder = forwarder_str))
                      
        return ExportDirData(
                struct = export_dir,
                symbols = exports)
        
                    
    def get_dword_from_data(self, data, offset):
        return struct.unpack('<L', data[offset*4:(offset+1)*4])[0]
        
        
    def get_word_from_data(self, data, offset):
        return struct.unpack('<H', data[offset*2:(offset+1)*2])[0]


    def parse_delay_import_directory(self, rva, size):
        """Walk and parse the delay import directory."""
        
        import_descs =  []
        while True:
            try:
                # If the RVA is invalid all would blow up. Some PEs seem to be
                # specially nasty and have an invalid RVA.
                data = self.get_data(rva)
            except PEFormatError, e:
                break
                
            import_desc =  self.__unpack_data__(
                self.__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__,
                data, file_offset = self.get_offset_from_rva(rva) )
            
            
            # If the structure is all zeores, we reached the end of the list
            if not import_desc or import_desc.all_zeroes():
                break
            
            
            rva += import_desc.sizeof()
            
            try:
                import_data =  self.parse_imports(
                    import_desc.pINT,
                    import_desc.pIAT,
                    None)
            except PEFormatError, e:
                break
            
            if not import_data:
                continue
            
            
            dll = self.get_string_at_rva(import_desc.szName)
            if dll:
                import_descs.append(
                    ImportDescData(
                        struct = import_desc,
                        imports = import_data,
                        dll = dll))
        
        return import_descs

                    

    def parse_import_directory(self, rva, size):
        """Walk and parse the import directory."""

        import_descs =  []
        while True:
            try:
                # If the RVA is invalid all would blow up. Some EXEs seem to be
                # specially nasty and have an invalid RVA.
                data = self.get_data(rva)
            except PEFormatError, e:
                break
                
            import_desc =  self.__unpack_data__(
                self.__IMAGE_IMPORT_DESCRIPTOR_format__,
                data, file_offset = self.get_offset_from_rva(rva) )
                
                
            # If the structure is all zeores, we reached the end of the list
            if not import_desc or import_desc.all_zeroes():
                break
                
            
            rva += import_desc.sizeof()
                        
            try:
                import_data =  self.parse_imports(
                    import_desc.OriginalFirstThunk,
                    import_desc.FirstThunk,
                    import_desc.ForwarderChain)
            except PEFormatError, e:
                break
                
            if not import_data:
                continue
                
                
            dll = self.get_string_at_rva(import_desc.Name)
            if dll:
                import_descs.append(
                    ImportDescData(
                        struct = import_desc,
                        imports = import_data,
                        dll = dll))

        return import_descs
            

    
    def parse_imports(self, original_first_thunk, first_thunk, forwarder_chain):
        """Parse the imported symbols.
        
        It will fill a list, which will be avalable as the dictionary
        attribute "imports". Its keys will be the DLL names and the values
        all the symbols imported from that object.
        """
        
        imported_symbols = []
        imports_section = self.get_section_by_rva(first_thunk)
        if not imports_section:
            raise PEFormatError, 'Invalid/corrupted imports.'
            
        
        # Import Lookup Table. Contains ordinals or pointers to strings.
        ilt = self.get_import_table(original_first_thunk)
        # Import Address Table. May have identical content to ILT if
        # PE file is not bounded, Will contain the address of the
        # imported symbols once the binary is loaded or if it is already
        # bound.
        iat = self.get_import_table(first_thunk)

        # OC Patch:
        # Would crash if iat or ilt had None type 
        if not iat and ilt:
            table = ilt
        elif iat and not ilt:
            table = iat
        elif (len(ilt) and len(iat)==0) or (len(ilt) == len(iat)):
            table = ilt
        elif len(ilt)==0 and len(iat):
            table = iat
        else:
            return None
            
        for idx in range(len(table)):

            imp_ord = None
            imp_name = None
                        
            if table[idx].AddressOfData:
            
                if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
                    ordinal_flag = IMAGE_ORDINAL_FLAG
                elif self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
                    ordinal_flag = IMAGE_ORDINAL_FLAG64
            
                # If imported by ordinal, we will append the ordinal number.
                if table[idx].AddressOfData & ordinal_flag:
                    imp_ord = table[idx].AddressOfData & 0xffff
                    imp_name = None
                else:
                    try:
                        data = self.get_data(table[idx].AddressOfData, 2)
                        imp_ord = self.get_word_from_data(data, 0)
                        imp_name = self.get_string_at_rva(table[idx].AddressOfData+2)
                    except PEFormatError, e:
                        pass

            imp_address = first_thunk+self.OPTIONAL_HEADER.ImageBase+idx*4
                
            if iat and ilt and ilt[idx].AddressOfData != iat[idx].AddressOfData:
                imp_bound = iat[idx].AddressOfData
            else:
                imp_bound = None
                
            if imp_name != '' and (imp_ord or imp_name):
                imported_symbols.append(
                    ImportData(
                        ordinal = imp_ord,
                        name = imp_name,
                        bound = imp_bound,
                        address = imp_address))
            
        return imported_symbols
                


    def get_import_table(self, rva):
    
        table = []
        
        while True and rva:
            try:
                data = self.get_data(rva)
            except PEFormatError, e:
                return None
                
            if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
                format = self.__IMAGE_THUNK_DATA_format__
            elif self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
                format = self.__IMAGE_THUNK_DATA64_format__
                
            thunk_data = self.__unpack_data__(
                format, data, file_offset=self.get_offset_from_rva(rva) )
                    
            if not thunk_data or thunk_data.all_zeroes():
                break
                
            rva += thunk_data.sizeof()
            
            table.append(thunk_data)
            
        return table
    
    def get_memory_mapped_image(self):
        """Returns the data corresponding to the memory layout of the PE file.
        
        The data includes the PE header and the sections loaded at offsets
        corresponding to their relative virtual addresses. (the VirtualAddress
        section header member).
        Any offset in this data corresponds to the absolute memory address
        ImageBase+offset.
        """
        
        # Collect all sections in one code block    
        data = self.header
        for section in self.sections:
        
            padding_length = section.VirtualAddress - len(data)
            
            if padding_length>0:
                data += '\0'*padding_length
            elif padding_length<0:
                data = data[:padding_length]
                
            data += section.data
            
        return data

            
    def get_data(self, rva, length=None):
        """Get data regardless of the section where it lies on.
        
        Given a rva and the size of the chunk to retrieve, this method
        will find the section where the data lies and return the data.
        """
        
        s = self.get_section_by_rva(rva)
        if not s:
            if rva<len(self.header):
                if length:
                    end = rva+length
                else:
                    end = None
                return self.header[rva:end]
                
            raise PEFormatError, 'data at RVA can\'t be fetched. Corrupted header?'
            
        return s.get_data(rva, length)


    def get_offset_from_rva(self, rva):
        """Get the file offset corresponding to this rva.
        
        Given a rva , this method will find the section where the
        data lies and return the offset within the file.
        """
        
        s = self.get_section_by_rva(rva)
        if not s:
                
            raise PEFormatError, 'data at RVA can\'t be fetched. Corrupted header?'
            
        return s.get_offset_from_rva(rva)
        
            
    def get_string_at_rva(self, rva):
        """Get an ASCII string located at the given address."""

        s = self.get_section_by_rva(rva)
        if not s:
            if rva<len(self.header):
                return self.get_string_from_data(rva, self.header)
            return None
                
        return self.get_string_from_data(rva-s.VirtualAddress, s.data)
        
        
    def get_string_from_data(self, offset, data):
        """Get an ASCII string from within the data."""

        # OC Patch
        b = None
        
        try:
            b = data[offset]
        except IndexError:
            return ''
        
        s = ''
        while ord(b):
            s += b
            offset += 1
            try:
                b = data[offset]
            except IndexError:
                break
          
        return s

                
    def get_string_u_at_rva(self, rva):
        """Get an Unicode string located at the given address."""
        
        try:
            # If the RVA is invalid all would blow up. Some EXEs seem to be
            # specially nasty and have an invalid RVA.
            data = self.get_data(rva, 2)
        except PEFormatError, e:
            return None

        length = struct.unpack('<H', data)[0]
        
        s = ''
        for idx in range(length):
            try:
                uchr = struct.unpack('<H', self.get_data(rva+2*(idx+1), 2))[0]
            except struct.error:
                break
            s += unichr(uchr)
          
        return s

                
    def get_section_by_rva(self, rva):
        """Get the section containing the given address."""
    
        sections = [s for s in self.sections if s.contains(rva)]
        
        if sections:
            return sections[0]
                    
        return None

    
    def __str__(self):
        return self.dump_info()
    
            
    def print_info(self):
        """Print all the PE header information in a human readable from."""
        print self.dump_info()
        
        
    def dump_info(self):
        """Dump all the PE header information into human readable string."""
        
        
        dump = Dump()
        
        dump.add_header('DOS_HEADER')
        dump.add_lines(self.DOS_HEADER.dump())
        dump.add_newline()
        
        dump.add_header('NT_HEADERS')
        dump.add_lines(self.NT_HEADERS.dump())
        dump.add_newline()
        
        dump.add_header('FILE_HEADER')
        dump.add_lines(self.FILE_HEADER.dump())
        
        image_flags = self.retrieve_flags(IMAGE_CHARACTERISTICS, 'IMAGE_FILE_')
            
        dump.add('Flags: ')
        flags = []
        for flag in image_flags:
            if getattr(self.FILE_HEADER, flag[0]):
                flags.append(flag[0])
        dump.add_line(', '.join(flags))
        dump.add_newline()
        
        dump.add_header('OPTIONAL_HEADER')
        dump.add_lines(self.OPTIONAL_HEADER.dump())
        dump.add_newline()
        
        
        dump.add_header('PE Sections')
        
        section_flags = self.retrieve_flags(SECTION_CHARACTERISTICS, 'IMAGE_SCN_')
        
        for section in self.sections:
            dump.add_lines(section.dump())
            dump.add('Flags: ')
            flags = []
            for flag in section_flags:
                if getattr(section, flag[0]):
                    flags.append(flag[0])
            dump.add_line(', '.join(flags))
            dump.add_newline()
            
            
        dump.add_header('Directories')
        for idx in range(len(self.OPTIONAL_HEADER.DATA_DIRECTORY)):
            directory = self.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
            dump.add_lines(directory.dump())
        dump.add_newline()

            
        if hasattr(self, 'DIRECTORY_ENTRY_EXPORT'):
            dump.add_header('Exported symbols')
            dump.add_lines(self.DIRECTORY_ENTRY_EXPORT.struct.dump())
            dump.add_newline()
            dump.add_line('%-10s   %-10s  %s' % ('Ordinal', 'RVA', 'Name'))
            for export in self.DIRECTORY_ENTRY_EXPORT.symbols:
                dump.add('%-10d 0x%08X    %s' % (
                    export.ordinal, export.address, export.name))
                if export.forwarder:
                    dump.add_line(' forwarder: %s' % export.forwarder)
                else:
                    dump.add_newline()
                
            dump.add_newline()
        
        if hasattr(self, 'DIRECTORY_ENTRY_IMPORT'):
            dump.add_header('Imported symbols')
            for module in self.DIRECTORY_ENTRY_IMPORT:
                dump.add_lines(module.struct.dump())
                dump.add_newline()
                for symbol in module.imports:
                    dump.add('%s.%s Ord[%s]' % (
                        module.dll, symbol.name, str(symbol.ordinal)))
                    if symbol.bound:
                        dump.add_line(' Bound: 0x%08X' % (symbol.bound))
                    else:
                        dump.add_newline()
                dump.add_newline()
                
        
        if hasattr(self, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
            dump.add_header('Bound imports')
            for bound_imp_desc in self.DIRECTORY_ENTRY_BOUND_IMPORT:
            
                dump.add_lines(bound_imp_desc.struct.dump())
                dump.add_line('DLL: %s' % bound_imp_desc.name)
                dump.add_newline()
                
                for bound_imp_ref in bound_imp_desc.entries:
                    dump.add_lines(bound_imp_ref.struct.dump(), 4)
                    dump.add_line('DLL: %s' % bound_imp_ref.name, 4)
                    dump.add_newline()


        if hasattr(self, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            dump.add_header('Delay Imported symbols')
            for module in self.DIRECTORY_ENTRY_DELAY_IMPORT:
            
                dump.add_lines(module.struct.dump())
                dump.add_newline()
                
                for symbol in module.imports:
                    dump.add('%s.%s Ord[%s]' % (
                        module.dll, symbol.name, str(symbol.ordinal)))
                    
                    if symbol.bound:
                        dump.add_line(' Bound: 0x%08X' % (symbol.bound))
                    else:
                        dump.add_newline()
                dump.add_newline()
            
        
        if hasattr(self, 'DIRECTORY_ENTRY_RESOURCE'):
            dump.add_header('Resource directory')
            
            dump.add_lines(self.DIRECTORY_ENTRY_RESOURCE.struct.dump())
            
            for resource_type in self.DIRECTORY_ENTRY_RESOURCE.entries:
            
                if resource_type.name is not None:
                    dump.add_line('Name: [%s]' % resource_type.name, 2)
                else:
                    dump.add_line('Id: [%X] (%s)' % (
                        resource_type.struct.Id, RESOURCE_TYPE.get(
                            resource_type.struct.Id, '-')),
                        2)
                        
                dump.add_lines(resource_type.struct.dump(), 2)

                dump.add_lines(resource_type.directory.struct.dump(), 4)
                    
                for resource_id in resource_type.directory.entries:
                
                    if resource_id.name is not None:
                        dump.add_line('Name: [%s]' % resource_id.name, 6)
                    else:
                        dump.add_line('Id: [%X]' % resource_id.struct.Id, 6)
                        
                    dump.add_lines(resource_id.struct.dump(), 6)

                    dump.add_lines(resource_id.directory.struct.dump(), 8)
                        
                    for resource_lang in resource_id.directory.entries:
                    #    dump.add_line('\\--- LANG [%d,%d][%s]' % (
                    #        resource_lang.data.lang,
                    #        resource_lang.data.sublang,
                    #        LANG[resource_lang.data.lang]), 8)
                        dump.add_lines(resource_lang.struct.dump(), 10)
                        dump.add_lines(resource_lang.data.struct.dump(), 12)
                dump.add_newline()
    
            dump.add_newline()
        
        
        dump.add_header('TLS')
        if hasattr(self, 'DIRECTORY_ENTRY_TLS') and self.DIRECTORY_ENTRY_TLS:
            dump.add_lines(self.DIRECTORY_ENTRY_TLS.struct.dump())
        dump.add_newline()

        
        if hasattr(self, 'DIRECTORY_ENTRY_DEBUG'):
            dump.add_header('Debug information')
            for dbg in self.DIRECTORY_ENTRY_DEBUG:
                dump.add_lines(dbg.struct.dump())
                try:
                    dump.add_line('Type: '+DEBUG_TYPE[dbg.struct.Type])
                except KeyError:
                    dump.add_line('Type: %x(Unknown)' % dbg.struct.Type)
                dump.add_newline()
        
        
        if hasattr(self, 'DIRECTORY_ENTRY_BASERELOC'):
            dump.add_header('Base relocations')
            for base_reloc in self.DIRECTORY_ENTRY_BASERELOC:
                dump.add_lines(base_reloc.struct.dump())
                for reloc in base_reloc.entries:
                    try:
                        dump.add_line('%08X %s' % (
                            reloc.rva, RELOCATION_TYPE[reloc.type][16:]), 4)
                    except KeyError:
                        dump.add_line('%08X %x(Unknown)' % (
                            reloc.rva, reloc.type), 4)
                dump.add_newline()
        

        return dump.get_text()

    # OC Patch
    def get_physical_by_rva(self, rva):
        """Gets the physical address in the PE file from an RVA value."""
        # Get the section of the RVA
        section = self.get_section_by_rva(rva)

        # If the section can't be found, return an error
        if not section:
            return None

        # Calculate the displacement between that section and the virtual
        phystovirt = section.VirtualAddress - section.PointerToRawData

        # Calculate offset relevant to that rva
        return rva - phystovirt
        
####################################################################################################
####################################################################################################
# end of pefile


import sys
import time
import os


if len(sys.argv) != 2:
    print "Usage: ./idl_dump.py <dir>"
    sys.exit(1)

# grab directory to walk
path = sys.argv[1]

if path.endswith(".dll") or path.endswith(".exe"):
    print "[!] Please provide a path to a directory, not a filename"
    sys.exit(1)
    
print "[*] Searching recursively for RPC servers in %s ..." % path

# list of 'good' extensions
good_ext = ['dll', 'exe']

flag         = 0
file_counter = 0
func_counter = 0
image_list   = []

# walk the given directory
for dot, dirs, files in os.walk(path):
    for fd in files:

        # determine if its a good extension
        ext = fd[-3:]
        if ext.lower() in good_ext:
            full_path = dot + "\\" + fd
            file_counter += 1
            
            # load the PE
            try:
                pe = PE(full_path)
                sys.stdout.write("[*] Parsing %s ...                      \r" % fd)
                sys.stdout.flush()
            except:
                print "[!] Problem loading PE file %s... continuing" % full_path
                pass
        
            # grab imports
            try:
                for dll in pe.DIRECTORY_ENTRY_IMPORT: 
                    for func in dll.imports:
                        if func.name.startswith("RpcServer"):
                            print "[+] %s in %s" % (func.name, full_path)
                            
                            if flag == 0:
                                image_list.append((fd, full_path))
                                flag = 1
                            
                            func_counter += 1
                del pe
            except:
                pass
  
        flag = 0
                
sys.stdout.write("                                                   \r")

print "[*] Found a total of %d RPC server(s) functions in %d files." % (func_counter, file_counter)
print "---"

output_dir = "MIDLdb"

try:
    os.mkdir(output_dir)
except OSError:
    pass
    
for image_name, image in image_list:
    print "[+] Processing %s ..." % image
    
    mida_path = output_dir + "\\%s.idl" % image_name
    
    os.system("\"C:\Program Files\IDA\idaw.exe\" -A -Smida.idc -Oofile:%s %s" % (mida_path, image))
    
    idb_path = image[:-4]
    idb_path += ".idb"
    os.system("mv \"%s\" \"IDBdb\\%s.idb\"" % (idb_path, image_name))