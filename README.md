# 🌐 DNSIP — Kişisel Dinamik DNS (DuckDNS) Sistemi (Sunucu + Windows & macOS İstemcisi)

Bu proje, kendi alan adınız (`*.alanadiniz.com` veya `*.ddns.alanadiniz.com`) üzerinde çalışan, **tam teşekküllü bir DuckDNS klonu** (Otoriter DNS Sunucusu + Web Yönetim Paneli + Token/API Sistemi) ve **hem Windows hem de macOS** üzerinde çalışan **Sistem Tepsisi (System Tray / Menu Bar) destekli masaüstü istemcisinden** oluşur.

---

## 📁 Proje Klasör Yapısı

```text
dnsip/
├── server/                      # VPS üzerinde çalışacak DuckDNS Sunucusu
│   ├── app.py                   # Web Yönetim Paneli + DuckDNS (/update) & JSON REST API
│   ├── dns_engine.py            # Saf Python Otoriter DNS Sunucusu (UDP/TCP Port 53) + Cloudflare Köprüsü
│   ├── database.py              # SQLite veritabanı (Kullanıcı, Token, Alt Alan Adları ve IP Logları)
│   ├── setup_vps.sh             # Ubuntu/Debian VPS için tek komutla otomatik kurulum betiği
│   ├── Dockerfile               # Docker imaj tanımı
│   └── docker-compose.yml       # Docker Compose yapılandırması
│
└── client/                      # Windows & macOS Masaüstü İstemcisi (GUI + System Tray + Daemon)
    ├── ddns_client.py           # Görsel Arayüz (GUI), Sistem Tepsisi (Tray) ve Arka Plan Servisi
    ├── autostart.py             # Windows Registry & macOS LaunchAgent otomatik başlatma modülü
    ├── requirements.txt         # İstemci paketleri (pystray, Pillow, pyinstaller)
    ├── run_windows.bat          # Windows için tek tıkla çalıştırıcı
    ├── build_windows_exe.bat    # Windows için tek dosya DNSIP-Client.exe derleyici
    ├── run_macos.command        # macOS için çift tıklanabilir çalıştırıcı
    └── build_macos_app.sh       # macOS için "DNSIP Client.app" uygulama paketi derleyici
```

---

## 🚀 1. Adım: VPS Sunucusunun Kurulumu

Sunucu tarafı harici hiçbir Python kütüphanesine ihtiyaç duymadan (Python 3.8+ standart kütüphanesi ile) hem **UDP/TCP Port 53 DNS Sunucusunu** hem de **Port 8080 Web Panelini & API'yi** çalıştırır.

### Seçenek A: Linux VPS Üzerinde Tek Komutla Kurulum (Önerilen)
`server/` klasörünü VPS sunucunuza kopyalayın ve çalıştırın:
```bash
cd server
sudo bash setup_vps.sh
```
Bu betik:
1. Ubuntu/Debian'da Port 53'ü meşgul eden `systemd-resolved` çakışmasını otomatik çözer.
2. Alan adınızı, VPS IP adresinizi ve yönetici şifrenizi sorar.
3. `dnsip.service` adında bir `systemd` servisi kurar ve sunucu her açıldığında otomatik başlatır.

### Seçenek B: Docker ile Kurulum
```bash
cd server
DNSIP_BASE_DOMAIN=alanadim.com DNSIP_SERVER_IP=VPS_IP_ADRESINIZ docker compose up -d
```

---

## 🔗 2. Adım: Kendi Alan Adınızı (Domain) Bağlama

Alan adınızı sunucunuza **3 farklı yöntemden** dilediğiniz biriyle bağlayabilirsiniz:

### Yöntem 1: Tam Bağımsız Otoriter DNS (Gerçek DuckDNS Yöntemi - Port 53)
1. Domain kayıt firmanızın (Namecheap, GoDaddy, Natro, Güzel Hosting, Cloudflare Registrar vb.) panelinden **Özel Nameserver (Glue Record / Child Nameserver)** bölümüne girin:
   - `ns1.alanadim.com` &rarr; `VPS_IP_ADRESINIZ`
   - `ns2.alanadim.com` &rarr; `VPS_IP_ADRESINIZ`
2. Alan adınızın **Nameserver (NS)** adreslerini `ns1.alanadim.com` ve `ns2.alanadim.com` olarak değiştirin.
3. Artık `ev.alanadim.com`, `macbook.alanadim.com`, `ofis.alanadim.com` gibi tüm alt alan adlarınız doğrudan VPS'inizdeki `dns_engine.py` tarafından yanıtlanır!

### Yöntem 2: Alt Alan Adı (Subdomain) NS Delegasyonu
Ana alan adınızın mevcut DNS kayıtlarını (e-posta, web sitesi vb.) bozmak istemiyorsanız, mevcut DNS panelinizde sadece şu 2 kaydı ekleyin:
- `A` Kaydı: `ns1.alanadim.com` &rarr; `VPS_IP_ADRESINIZ`
- `NS` Kaydı: `ddns.alanadim.com` &rarr; `ns1.alanadim.com`
Web panelinde **Base Domain** kısmına `ddns.alanadim.com` yazın. Artık `ev.ddns.alanadim.com` adresleriniz dinamik DNS olarak çalışır.

### Yöntem 3: Cloudflare API Köprü Modu (Port 53 Ayarı Gerektirmez)
Alan adınız Cloudflare üzerindeyse, `http://VPS_IP:8080` Web Paneline girip **"Cloudflare DNS Senkronizasyonu"** kutusunu işaretleyin, **Cloudflare API Token** ve **Zone ID** bilgilerinizi kaydedin. İstemcilerinizden gelen her IP güncellemesi anında Cloudflare DNS tablonuza da işlenir.

---

## 💻 3. Adım: Windows & macOS Masaüstü Uygulaması Kurulumu

### Windows Üzerinde Çalıştırma
1. `client/run_windows.bat` dosyasına çift tıklayın (İlk çalışmada `.venv` oluşturur ve sistem tepsisi kütüphanelerini kurar).
2. İsterseniz tek dosya `.exe` üretmek için `client/build_windows_exe.bat` dosyasına çift tıklayın; `client/dist/DNSIP-Client.exe` oluşacaktır.

### macOS Üzerinde Çalıştırma
1. Terminal'de bir kez çalıştırma izni verin:
   ```bash
   chmod +x client/run_macos.command client/build_macos_app.sh
   ```
2. `run_macos.command` dosyasına çift tıklayarak başlatın veya `build_macos_app.sh` çalıştırarak `DNSIP Client.app` paketini oluşturup **Applications (Uygulamalar)** klasörünüze taşıyın.

### İstemci Özellikleri
- **Sistem Tepsisi (Windows System Tray & macOS Menu Bar)**: Pencereyi kapattığınızda uygulama kapanmaz, sağ altta (Windows) veya üst menü çubuğunda (macOS) renkli durum ikonuyla (🟢 Yeşil: Aktif, 🔴 Kırmızı: Hata) arka planda çalışmaya devam eder.
- **Otomatik Başlatma**: Arayüzdeki *"Bilgisayar açıldığında arka planda otomatik başlat"* seçeneğini işaretlediğinizde Windows Registry (`HKCU\...\Run`) veya macOS `LaunchAgents` (`~/Library/LaunchAgents/com.dnsip.client.plist`) kaydı otomatik oluşturulur.
- **DuckDNS %100 Protokol Uyumu**: Sunucunuz aynı zamanda standart DuckDNS URL yapısını destekler:
  ```text
  http://SUNUCU_ADRESINIZ:8080/update?domains=ev&token=TOKENINIZ&ip=
  ```
