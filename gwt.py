# -*- coding: utf-8 -*-
#!/usr/local/bin/python3
"""
gwt.py

About:
======

This tool is used to remotely fingerprint GWT endpoints and generate GWT serialized strings. 
These serialized strings can be used to test the endpoints for security vulnerabilities.

Notes:
======

- This code is far from complete and only handles a few data types
- The code is very ugly, because, lazy.

License:
========

Copyright (C) 2017 Steven Seeley of Source Incite

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import re
import sys
import random
import requests
from urllib.parse import urljoin
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from slimit import ast
from slimit.parser import Parser
from slimit.visitors import nodevisitor

from bs4 import BeautifulSoup

extracted = []

LONG    = "J"
DOUBLE  = "D"
FLOAT   = "F"
INT     = "I"
BYTE    = "B"
SHORT   = "S"
BOOLEAN = "Z"
CHAR    = "C"

STRING_OBJECT   = "java.lang.String"
INTEGER_OBJECT  = "java.lang.Integer"
DOUBLE_OBJECT   = "java.lang.Double"
FLOAT_OBJECT    = "java.lang.Float"
BYTE_OBJECT     = "java.lang.Byte"
BOOLEAN_OBJECT  = "java.lang.Boolean"
SHORT_OBJECT    = "java.lang.Short"
CHAR_OBJECT     = "java.lang.Char"
LONG_OBJECT     = "java.lang.Long"

# complex types
LIST_OBJECT     = "java.util.List"

known_objects = [STRING_OBJECT, INTEGER_OBJECT, DOUBLE_OBJECT, FLOAT_OBJECT, BYTE_OBJECT, BOOLEAN_OBJECT, SHORT_OBJECT, CHAR_OBJECT, LONG_OBJECT]

class bcolors:
    """
    colors in the terminal are fun, aight?
    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    @staticmethod
    def print_banner(string):
        print(bcolors.HEADER + string + bcolors.ENDC)

    @staticmethod
    def print_warning(string):
        print(bcolors.WARNING + string + bcolors.ENDC)

    @staticmethod
    def print_good(string):
        print(bcolors.OKBLUE + string + bcolors.ENDC)

    @staticmethod
    def print_decent(string):
        print (bcolors.OKGREEN + string + bcolors.ENDC)

    @staticmethod
    def print_fail(string):
        print (bcolors.FAIL + string + bcolors.ENDC)

def parse_JavaScript(js):
    global functions
    parser = Parser()
    tree = parser.parse(js)

    for node in nodevisitor.visit(tree):
        if isinstance(node, ast.FuncDecl):
            if len(node.parameters) > 1:
                last  = node.parameters[len(node.parameters)-1]
                first = node.parameters[0]

                # check for the first parameter
                if first.value == "this$static":

                    # check that the last one is a callback
                    if last.value == "callback":

                        # the function will call createStreamWriter if its used in the client interface
                        if "createStreamWriter" in node.to_ecma():
                            params = []

                            # if we have function arguments
                            if len(node.parameters) > 2:

                                # -2 for the 'this' and callback
                                num_of_params = len(node.parameters)-2

                                for param in node.parameters:

                                    # we just append the arguments we will need to make in the GWT request
                                    if param.value != "this$static" and param.value != "callback":
                                        params.append(param.value)

                            # else we have no arguments
                            else:
                                num_of_params = 0

                            # strip the correct function name
                            function = node.identifier.value.replace("$","")
                            function = re.sub('_\d+', '', function)

                            # append to a list, since we my have functions of the same name, but different signatures
                            extracted.append({ "function":      function, 
                                               "num_of_args":   num_of_params, 
                                               "args":          params,
                                               "arg_type_data": get_param_types(function, node.to_ecma()) })

def get_param_types(function, js):
    """
    This method extracts the paramter types from the function.
    """
    strings = []
    parser = Parser()
    tree = parser.parse(js)
    for node in nodevisitor.visit(tree):
        if isinstance(node, ast.String):
            value = node.value.replace("'", "")
            if value != "":
                strings.append(value)

    # now we patch the list to remove unwanted values
    i = strings.index(function)

        # slice the array
    return strings[i-1:]


def build_gwt(e, url, strong_name, type_data):
    """
    This method will build the GWT. 
    Please note, this only handles types for:

     - java.lang.Integer
     - java.lang.Long
     - java.lang.String
     - java.lang.Boolean
     - java.util.List

    It will not:
     - develop complex multi demensional Lists
     - try to use custom data types other then defining it as <type>:<string>

    I do not garrentee this method will develop a 100% correct GWT serialized string.
    """

    client_class   = type_data[0]
    function       = e["function"]

    # 4 is the base number of strings for the GWT. Then we double the args to account for name:value pairs.
    number_of_args = (e["num_of_args"] * 2) + 4

    args = 4                 # this is the minimum.

    # the GWT payload
    gwt = []
    gwt.append("6")          # version
    gwt.append("0")          # dunno
    gwt.append(args)         # the number of elements (patched later)
    gwt.append(url)          # the endpoint URL
    gwt.append(strong_name)  # the strong name (not a CSRF token)
    gwt.append(client_class) # the client class exposed endpoint
    gwt.append(function)     # the function we are targeting

    # this is where we access the type data
    if e["num_of_args"] > 0:
        # 3 is the index of the 
        for i in range(3, e["num_of_args"]+3):

            # yep, wtf.

            if INTEGER_OBJECT in type_data[i]:
                
                # Just a single param

                args += 1
                gwt.append(type_data[i])

            elif LONG_OBJECT in type_data[i]:
                # 
                args += 1
                gwt.append(type_data[i])

            elif STRING_OBJECT in type_data[i]:
                
                # two params, name:value pair
                args += 2
                gwt.append(type_data[i])

            elif type_data[i].startswith("java.util.List"):
                
                # If its a java.util.List, we send a list of type ArrayList with a single string inside.
                # It is up to the tester to modify this manually to perform further, complicated attacks.
                # This is four params. 1: List, 2: List type, 3: String type, 4: String value

                args += 4
                gwt.append(type_data[i])
                gwt.append("java.util.ArrayList")
                gwt.append("java.lang.String")
            
            elif type_data[i] == BOOLEAN:

                type_data[i] = BOOLEAN_OBJECT
                args += 1

                gwt.append(BOOLEAN_OBJECT)

            else:
                
                # treated like a string
                args += 2

                # else its an unknown type so just append
                gwt.append(type_data[i])

    # this appends the fuzz strings
    if e["num_of_args"] > 0:
        for i in range(3, e["num_of_args"] + 3):

            # please, dont try to understand this logic...
            if STRING_OBJECT in type_data[i]:
                gwt.append("%s")
            elif "/" in type_data[i]:
                raw_type = type_data[i].split("/")[0]
                if raw_type not in known_objects:
                    gwt.append("%s")
            elif type_data[i] not in known_objects:
                gwt.append("%s")
            
    # now we patch the args
    gwt[2] = str(args)

    # these are the first 4 args
    gwt.append("1")
    gwt.append("2")
    gwt.append("3")
    gwt.append("4")
    
    # add the number of args
    gwt.append(str(e["num_of_args"]))
    offset = 0

    if e["num_of_args"] > 0:
        for i in range(5, args+1):
            gwt.append(str(i))
        
        for i in range(3, e["num_of_args"] + 3):
            array_index = 2 + i
            if BOOLEAN_OBJECT in type_data[i]:
                gwt.append(str(array_index)) # read in
                gwt.append("%i")   # fuzz value
            elif INTEGER_OBJECT in type_data[i]:
                gwt.append(str(array_index)) # read in
                gwt.append("%d")   # fuzz value
            elif LONG_OBJECT in type_data[i]:
                gwt.append(str(array_index)) # read in
                gwt.append("%l")   # fuzz value
    return gwt

def main(proxy=None):
    global functions
    if proxy:
        proxies = {'http': proxy, 'https': proxy}
    r = requests.get(t, verify=False, proxies=proxies)
    if r.status_code == 200:
        html_cache = re.findall( "([A-Z0-9]{30,35})", r.text )
    else:
        "(-) the path doesn't exist!"

    file = random.choice(html_cache)

    c = {}
    if options.cookies:
        cookies = options.cookies.split(",")
        for cookie in cookies:
            c[cookie.split(":")[0]] = cookie.split(":")[1]

    r = requests.get(urljoin(t, "%s.cache.html" % file), cookies=c, verify=False)
    if r.status_code == 200:
        print("(+) parsing %s.cache.html...\r\n" % file)
        soup = BeautifulSoup(r.text, "html.parser")
        for tag in soup.findAll("script"):
            raw_js = str(tag.next).replace("<!--", "").replace("-->","")
            parse_JavaScript(raw_js)

    for i, e in enumerate(extracted):
        i += 1
        bcolors.print_banner("(%02d) function: %s " % (i, e["function"]))
        if options.verbose:
            bcolors.print_banner("(%02d) number of parameters: %s " % (i, e["num_of_args"]))
            if e["num_of_args"] > 0:
                bcolors.print_banner("(%02d) parameters: %s " % (i, ", ".join(e["args"])))
            url = t.replace(t.split("/")[len(t.split("/"))-1], "")
            gwt = build_gwt(e, url, file, e['arg_type_data'])
            gwt_str = "|".join(gwt) + "|"
            bcolors.print_good("(%02d) GWT: %s\r\n" % (i, gwt_str))

def banner():
    return "\r\n| GWT generator - mr_me 2017 |\r\n"

if __name__ == '__main__':
    global t

    from optparse import OptionParser
     
    usage = "./%prog <[options]> -u <target>"
    usage += "\nExample: ./%prog -p localhost:8080 -c JSESSIONID:DB2CAA3D435241E0F19FD5075A1CE69D -u https://abc.xyz/some_gwt/some_gwt.nocache.js"
     
    parser = OptionParser(usage=usage)
    parser.add_option("-q", "--quiet",
                      action="store_false", dest="verbose", default=True,
                      help="don't print status messages to stdout")

    parser.add_option("-c", "--cookies",type="string", action="store", dest="cookies",
                      help="authenication cookies")

    parser.add_option("-p", "--proxy", type="string",action="store", dest="proxy",
                      help="HTTP Proxy <server:port>")

    parser.add_option("-u", "--url", type="string", action="store", dest="target",
                      help="The target endpoint using *.nocache.js")

    (options, args) = parser.parse_args()

    print(banner())

    if len(sys.argv) < 3:
        parser.print_help()
        sys.exit(1)

    if options.cookies:
        if ":" not in options.cookies:
            print("(-) cookies defined as <name>:<value>,<name><value>")
            parser.print_help()
            sys.exit(1)

    t = options.target
    main(proxy=options.proxy)
