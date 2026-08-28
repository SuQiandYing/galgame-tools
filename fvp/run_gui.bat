@echo off
setlocal
cd /d "%~dp0"

rem Make src-layout package importable even without pip install -e .
set "PYTHONPATH=%~dp0src;%PYTHONPATH%"

echo [INFO] Tool root: %CD%
echo [INFO] PYTHONPATH: %~dp0src

echo [INFO] Starting HCB Tool GUI...
python -m hcb_tool.gui.main_window
if errorlevel 1 (
  echo.
  echo [ERROR] GUI start failed.
  echo [FIX 1] Run: python -m pip install -e "%~dp0"
  echo [FIX 2] Or check whether your Python has tkinter installed.
  echo.
  pause
  exit /b 1
)

pause
