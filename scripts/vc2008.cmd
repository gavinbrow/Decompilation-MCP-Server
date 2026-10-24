@echo off
setlocal
set "FNV_VC=%~dp0..\tools\vc2008\VC"
set "PATH=%FNV_VC%\bin;%FNV_VC%\redist\x86\Microsoft.VC90.CRT;%PATH%"
set "INCLUDE=%FNV_VC%\include;%FNV_VC%\PlatformSDK\include"
set "LIB=%FNV_VC%\lib;%FNV_VC%\PlatformSDK\lib"
if not exist "%FNV_VC%\bin\cl.exe" (
  echo VC2008 compiler missing. See README.md.
  exit /b 1
)
if "%~1"=="" (
  cl.exe
) else (
  %*
)
exit /b %ERRORLEVEL%
