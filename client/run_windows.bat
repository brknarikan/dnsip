@echo off
chcp 65001 >nul
title DNSIP Masaustu Istemcisi (Windows)
cd /d "%~dp0"

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python bulunamadi. Lutfen https://www.python.org/downloads/ adresinden Python 3.11+ kurun
    echo     veya PowerShell'de: winget install Python.Python.3.12 komutunu calistirin.
    pause
    exit /b 1
)

if not exist ".venv" (
    echo [*] Ilk calistirma: Sanal ortam ve Sistem Tepsisi kutuphaneleri kuruluyor...
    python -m venv .venv
    call .venv\Scripts\activate.bat
    pip install --upgrade pip >nul 2>&1
    pip install pystray Pillow
) else (
    call .venv\Scripts\activate.bat
)

start "" .venv\Scripts\pythonw.exe ddns_client.py
exit
