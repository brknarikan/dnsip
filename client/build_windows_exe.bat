@echo off
chcp 65001 >nul
title DNSIP - Windows Tek Dosya EXE Olusturucu
cd /d "%~dp0"

if not exist ".venv" (
    python -m venv .venv
)
call .venv\Scripts\activate.bat
pip install -r requirements.txt

echo [*] DNSIP-Client.exe derleniyor...
pyinstaller --noconfirm --onefile --windowed --name "DNSIP-Client" ddns_client.py

echo.
echo [OK] Derleme tamamlandi!
echo Dosya konumu: %~dp0dist\DNSIP-Client.exe
pause
