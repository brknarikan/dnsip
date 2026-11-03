#!/usr/bin/env bash
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[!] Python3 bulunamadı. Lütfen 'brew install python-tk' veya python.org üzerinden Python 3 kurun."
  read -p "Çıkmak için Enter'a basın..."
  exit 1
fi

if [ ! -d ".venv" ]; then
  echo "[*] İlk çalıştırma: Sanal ortam ve macOS Menü Çubuğu (Tray) kütüphaneleri kuruluyor..."
  python3 -m venv .venv
  source .venv/bin/activate
  pip install --upgrade pip >/dev/null 2>&1
  pip install pystray Pillow
else
  source .venv/bin/activate
fi

python3 ddns_client.py &
exit 0
