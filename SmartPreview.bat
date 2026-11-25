@echo off
rem Double-click on Windows: starts the SmartPreview connector (and PhotoCraft, if it is not running).
cd /d "%~dp0connector"
where py >nul 2>nul && (py -3 smartpreview.py %*) || (python smartpreview.py %*)
pause
