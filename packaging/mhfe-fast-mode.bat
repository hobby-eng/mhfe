@echo off
rem Starts the fast mode for the browser tool in this folder: mhfe reads mhfe-fast-mode.sha256
rem next to it, checks the HTML file named there and serves it to this computer's browser.
cd /d "%~dp0"
mhfe.exe
pause
