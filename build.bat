@echo off

IF [%1]==[] GOTO BAD_COMMAND

set PERFORCE=p4
set VC14="c:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\IDE\devenv"
set VC11="c:\Program Files (x86)\Microsoft Visual Studio 11.0\Common7\IDE\devenv"
set VC10="c:\Program Files (x86)\Microsoft Visual Studio 10.0\Common7\IDE\devenv"
set VC9="c:\Program Files (x86)\Microsoft Visual Studio 9.0\Common7\IDE\devenv"

%PERFORCE% edit .../*.a
%PERFORCE% edit .../*.lib
%PERFORCE% edit .../*.dll
%PERFORCE% edit .../*.pdb
%PERFORCE% edit .../*.pri
%PERFORCE% edit lib/...
%PERFORCE% edit output/...

@del *.ncb
@del *.user

@echo Building libpthread x64 debug
%VC14%  libpthread.sln %1 "Debug|x64">build.txt
if errorlevel 1 goto ERROR_OUT

@echo Building libpthread x64 release
%VC14%  libpthread.sln %1 "Release|x64">build.txt
if errorlevel 1 goto ERROR_OUT

@echo Building libpthread Durango debug
%VC14%  libpthread.sln %1 "Debug|Durango">build.txt
if errorlevel 1 goto ERROR_OUT

@echo Building libpthread Durango release
%VC14%  libpthread.sln %1 "Release|Durango">build.txt
if errorlevel 1 goto ERROR_OUT


@echo Successful rebuild

::@echo Publishing binaries...
::call publish_apex.bat

%PERFORCE% revert -a ...

goto EXIT_END

:ERROR_OUT
@echo Encountered a compile error!
@echo See 'build.txt' in this directory for compile errors.

GOTO :EXIT_END

:BAD_COMMAND

@echo Missing command argument either /Build or /Rebuild


:EXIT_END
