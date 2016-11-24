from pykd import *
import re

"""
A simple windbg plugin that uses pykd to patch the peb->BeingDebugged.
"""

peb = getProcessOffset()
BeingDebugged = loadBytes(peb + 0x02, 0x1)[0]
if (BeingDebugged == 1):
	dprintln("(+) being debugged, patching...")
	writeBytes(peb + 0x2, [0x00])
	dprintln("(+) done!")
else:
	dprintln("(+) not being debugged")
