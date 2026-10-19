@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %ERRORLEVEL%==0 (
  py -3 "%~dp0tools\kdiag_lot1b\installer.py" install
) else (
  python "%~dp0tools\kdiag_lot1b\installer.py" install
)
exit /b %ERRORLEVEL%
