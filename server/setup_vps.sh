#!/usr/bin/env bash
set -e

echo "========================================================"
echo "  DNSIP — Kişisel DuckDNS Sunucusu VPS Kurulum Betiği"
echo "========================================================"

if [ "$EUID" -ne 0 ]; then
  echo "[!] Lütfen bu betiği root yetkisiyle çalıştırın: sudo bash setup_vps.sh"
  exit 1
fi

read -p "Ana alan adınızı girin (Örn: berkan.com veya ddns.berkan.com): " BASE_DOMAIN
BASE_DOMAIN=${BASE_DOMAIN:-ornekalanadi.com}

PUBLIC_IP=$(curl -4 -s https://api.ipify.org || curl -4 -s https://ifconfig.me || echo "127.0.0.1")
read -p "VPS Dış IP Adresiniz [$PUBLIC_IP]: " INPUT_IP
SERVER_IP=${INPUT_IP:-$PUBLIC_IP}

read -p "Web Paneli Admin Kullanıcı Adı [admin]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}

read -s -p "Web Paneli Admin Şifresi [admin123]: " ADMIN_PASS
echo ""
ADMIN_PASS=${ADMIN_PASS:-admin123}

# 1. Ubuntu/Debian systemd-resolved Port 53 çakışmasını çöz
if systemctl is-active --quiet systemd-resolved; then
  echo "[*] systemd-resolved Port 53 dinlemesi devre dışı bırakılıyor..."
  mkdir -p /etc/systemd/resolved.conf.d
  cat >/etc/systemd/resolved.conf.d/dnsip-port53.conf <<EOF
[Resolve]
DNS=1.1.1.1 8.8.8.8
DNSStubListener=no
EOF
  ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
  systemctl restart systemd-resolved
fi

# 2. Dosyaları /opt/dnsip-server dizinine kopyala
INSTALL_DIR="/opt/dnsip-server"
mkdir -p "$INSTALL_DIR/data"
cp -f database.py dns_engine.py app.py "$INSTALL_DIR/"

# 3. Systemd servisi oluştur
cat >/etc/systemd/system/dnsip.service <<EOF
[Unit]
Description=DNSIP Dynamic DNS Server (DuckDNS Clone)
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
Environment="DNSIP_BASE_DOMAIN=$BASE_DOMAIN"
Environment="DNSIP_NS1=ns1.$BASE_DOMAIN"
Environment="DNSIP_NS2=ns2.$BASE_DOMAIN"
Environment="DNSIP_SERVER_IP=$SERVER_IP"
Environment="DNSIP_ADMIN_USER=$ADMIN_USER"
Environment="DNSIP_ADMIN_PASS=$ADMIN_PASS"
Environment="DNSIP_DNS_PORT=53"
Environment="DNSIP_HTTP_PORT=8080"
ExecStart=/usr/bin/env python3 $INSTALL_DIR/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable dnsip.service
systemctl restart dnsip.service

# 4. Güvenlik duvarı (UFW) açıksa portları aç
if command -v ufw >/dev/null 2>&1; then
  ufw allow 53/udp >/dev/null 2>&1 || true
  ufw allow 53/tcp >/dev/null 2>&1 || true
  ufw allow 8080/tcp >/dev/null 2>&1 || true
fi

echo ""
echo "✅ Kurulum Tamamlandı!"
echo "--------------------------------------------------------"
echo "🌐 Web Yönetim Paneli : http://$SERVER_IP:8080"
echo "👤 Kullanıcı Adı      : $ADMIN_USER"
echo "🔑 Şifre              : (Belirlediğiniz şifre)"
echo "📡 DNS Sunucusu       : $SERVER_IP:53 (UDP/TCP)"
echo "--------------------------------------------------------"
