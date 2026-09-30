@echo off
REM AegisVision - start the local server and open the UI (http://127.0.0.1:8000)
cd /d "%~dp0"
if exist .venv\Scripts\activate.bat call .venv\Scripts\activate.bat
python -m backend.main --open %*
