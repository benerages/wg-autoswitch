@echo off
rem build.cmd - baut WG-AutoSwitch (wgas.exe = Dienst/CLI, wgas-gui.exe = Oberflaeche)
rem   build.cmd         Release fuer ARM64  -> build\arm64\wgas.exe + wgas-gui.exe
rem   build.cmd x64     Release fuer x64    -> build\x64\wgas.exe
rem   build.cmd test    Unit-Tests der Entscheidungslogik bauen und ausfuehren
rem Optional: set WGAS_SIGN_THUMB=<SHA1-Fingerabdruck> signiert mit einem Zertifikat aus dem Speicher.
rem Optional: set WGAS_NOWX=1 macht Warnungen nicht zu Fehlern.
setlocal EnableExtensions
cd /d "%~dp0"

set "HOSTARCH=x64"
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "HOSTARCH=arm64"

if /i "%~1"=="test" goto :test
set "ARCH=arm64"
if /i "%~1"=="x64" set "ARCH=x64"

call :vsenv %ARCH% || exit /b 1

set "OUT=build\%ARCH%"
if not exist "%OUT%" mkdir "%OUT%"

rem --- Meldungstabelle und Ressourcen
pushd "%OUT%"
mc -U ..\..\src\wgas_msg.mc || goto :fail_pop
rc /nologo /i . /i ..\..\src /fo wgas.res ..\..\src\wgas.rc || goto :fail_pop
rc /nologo /i ..\..\src /fo gui.res ..\..\src\gui.rc || goto :fail_pop
popd

rem --- Compiler/Linker gemaess Projektvorgaben
rem /MT + /NODEFAULTLIB:libucrt.lib ucrt.lib = statische vcruntime, dynamische UCRT (Teil von Windows 11)
set "CFLAGS=/nologo /std:c++20 /utf-8 /O1 /GL /GS /guard:cf /W4 /permissive- /EHs-c- /GR- /MT /Zc:inline"
set "CFLAGS=%CFLAGS% /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 /DNTDDI_VERSION=0x0A00000C"
if not defined WGAS_NOWX set "CFLAGS=%CFLAGS% /WX"
set "LFLAGS=/LTCG /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT /guard:cf /MANIFEST:EMBED"
set "LIBS=/NODEFAULTLIB:libucrt.lib ucrt.lib iphlpapi.lib wlanapi.lib advapi32.lib user32.lib wintrust.lib crypt32.lib bcrypt.lib version.lib"
if /i "%ARCH%"=="x64" set "LFLAGS=%LFLAGS% /CETCOMPAT"

rem Dienst + CLI
cl %CFLAGS% /I %OUT% /Fo%OUT%\ /Fe%OUT%\wgas.exe src\wgas.cpp src\common.cpp src\i18n.cpp %OUT%\wgas.res /link %LFLAGS% /SUBSYSTEM:CONSOLE %LIBS% || goto :fail
rem Oberflaeche
cl %CFLAGS% /I %OUT% /Fo%OUT%\ /Fe%OUT%\wgas-gui.exe src\gui.cpp src\update.cpp src\common.cpp src\i18n.cpp %OUT%\gui.res /link %LFLAGS% /SUBSYSTEM:WINDOWS %LIBS% gdi32.lib comctl32.lib comdlg32.lib shell32.lib winhttp.lib || goto :fail

if defined WGAS_SIGN_THUMB (
  signtool sign /fd SHA256 /sha1 %WGAS_SIGN_THUMB% /tr http://timestamp.digicert.com /td SHA256 %OUT%\wgas.exe %OUT%\wgas-gui.exe || goto :fail
)

echo.
for %%F in ("%OUT%\wgas.exe" "%OUT%\wgas-gui.exe") do echo OK: %%~fF - %%~zF Bytes
exit /b 0

:test
call :vsenv %HOSTARCH% || exit /b 1
if not exist build mkdir build
cl /nologo /std:c++20 /utf-8 /W4 /WX /EHsc /Fobuild\ /Febuild\test_decide.exe tests\test_decide.cpp || goto :fail
cl /nologo /std:c++20 /utf-8 /W4 /WX /EHsc /Fobuild\ /Febuild\test_i18n.exe tests\test_i18n.cpp || goto :fail
build\test_decide.exe || goto :fail
build\test_i18n.exe || goto :fail
exit /b 0

rem --- Visual-Studio-Umgebung laden, falls cl.exe nicht schon fuer das Ziel bereit ist
:vsenv
if /i "%VSCMD_ARG_TGT_ARCH%"=="%~1" exit /b 0
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo vswhere.exe nicht gefunden. Bitte "Build Tools fuer Visual Studio 2026" installieren:
  echo   Workload "Desktopentwicklung mit C++" inkl. "MSVC ARM64-Buildtools" und Windows 11 SDK.
  exit /b 1
)
set "VSDIR="
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR (
  echo Keine Visual-Studio-Installation gefunden.
  exit /b 1
)
set "VCARG=%HOSTARCH%_%~1"
if /i "%HOSTARCH%"=="%~1" set "VCARG=%~1"
call "%VSDIR%\VC\Auxiliary\Build\vcvarsall.bat" %VCARG% >nul || (
  echo vcvarsall.bat %VCARG% fehlgeschlagen - sind die Buildtools fuer %~1 installiert?
  exit /b 1
)
exit /b 0

:fail_pop
popd
:fail
echo.
echo BUILD FEHLGESCHLAGEN
exit /b 1
