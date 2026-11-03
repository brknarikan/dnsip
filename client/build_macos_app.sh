#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
pip install -r requirements.txt

echo "[*] macOS için 'DNSIP Client.app' uygulama paketi oluşturuluyor..."
pyinstaller --noconfirm --windowed --name "DNSIP Client" ddns_client.py

echo ""
echo "✅ Derleme tamamlandı!"
echo "Uygulama konumu: $(pwd)/dist/DNSIP Client.app"
echo "Bu .app dosyasını /Applications (Uygulamalar) klasörünüze sürükleyebilirsiniz."
