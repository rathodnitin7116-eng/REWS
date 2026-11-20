@echo off
title REWS - Ransomware Early Warning System
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (set PY=py) else (set PY=python)

%PY% -c "import flask" >nul 2>nul
if %errorlevel% neq 0 (
  echo Checking and installing dependencies...
  %PY% -m pip install -r requirements.txt
  if %errorlevel% neq 0 (
    echo Failed to install dependencies. Check Python and internet connection.
    pause
    exit /b 1
  )
)

start "" http://127.0.0.1:5000
%PY% app.py
pause
