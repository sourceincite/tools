@echo off

rem 	
rem This tool uncompressed compressed pdf files
rem to target raw objects inside pdf files.
rem 1. created a minset first
rem 2. run this foo over it
rem You will need pdftk.exe from: https://www.pdflabs.com/tools/pdftk-the-pdf-toolkit/

SET PDFTK=C:\PROGRA~1\PDFtk\bin\pdftk.exe

if [%1]==[] goto :usage
if [%2]==[] goto :usage

echo [+] input folder: %1 
if not exist %2\NUL (
  echo [+] output folder doesnt exist! making it...
  mkdir %2
)
echo [+] output folder: %2

@for /f %%a in ('2^>nul dir "%1\*.pdf" /a-d/b/-o/-p/s^|find /v /c ""') do set n=%%a
echo [+] found %n% pdf files
echo [+] processing...

rem the magic
for /f %%a IN ('dir /b /s "%1\*.pdf"') do %PDFTK% %%a output %2\%%~nxa uncompress 2>nul

rem now check how many were successfully done
@for /f %%a in ('2^>nul dir "%2\*.pdf" /a-d/b/-o/-p/s^|find /v /c ""') do set n=%%a
echo [+] successfully uncompressed %n% pdf files
goto :end

:usage
echo *** pdf toolkit decompression ***
echo [!] usage: %0 [input dir] [output dir]
goto :end
:end
