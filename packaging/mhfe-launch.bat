@echo off
rem Starts mhfe from this folder with its menu: choose a command with the arrow keys and Enter.
rem When a browser tool and its checksum file mhfe-fast-mode.sha256 lie here too, the first entry
rem serves that tool in fast mode. Commands with options are typed, such as mhfe encrypt --pim 1.
cd /d "%~dp0"
mhfe.exe
rem The window stays open after a failure, so that its message can be read.
if errorlevel 1 pause
