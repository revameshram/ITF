@echo off
REM AegisVision - one-time setup (Windows). Needs Python 3.10+ on PATH.
cd /d "%~dp0"
python -m venv .venv || goto :err
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt || goto :err
echo.
echo Setup complete. Start the app with run.bat
goto :eof
:err
echo Setup failed. Check that Python 3.10+ is installed and on PATH.
exit /b 1
