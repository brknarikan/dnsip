import argparse
import json
import os
import platform
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

from autostart import is_autostart_enabled, set_autostart

# Yapılandırma dosyası yolu (Windows AppData veya macOS ~/.dnsip)
if platform.system() == "Windows":
    CONFIG_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "DNSIPClient")
else:
    CONFIG_DIR = os.path.expanduser("~/.config/dnsip-client")

CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

DEFAULT_CONFIG = {
    "server_url": "http://127.0.0.1:8080",
    "api_token": "",
    "subdomains": "ev",
    "interval_minutes": 5,
    "auto_detect_external_ip": True,
    "auto_sync_enabled": True,
}


def load_config() -> Dict:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as fp:
                data = json.load(fp)
                merged = dict(DEFAULT_CONFIG)
                merged.update(data)
                return merged
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)


def save_config(cfg: Dict) -> None:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as fp:
        json.dump(cfg, fp, indent=2, ensure_ascii=False)


def get_client_device_info() -> str:
    os_name = platform.system()
    os_rel = platform.release()
    hostname = socket.gethostname()
    if os_name == "Darwin":
        os_label = f"macOS ({platform.mac_ver()[0] or os_rel})"
    elif os_name == "Windows":
        os_label = f"Windows {os_rel}"
    else:
        os_label = f"{os_name} {os_rel}"
    return f"{os_label} / {hostname}"


def fetch_external_ipv4() -> Optional[str]:
    """Harici güvenilir servislerden cihazın gerçek Public IPv4 adresini öğrenir."""
    endpoints = [
        "https://api.ipify.org",
        "https://ipv4.icanhazip.com",
        "https://ifconfig.me/ip",
    ]
    for url in endpoints:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "DNSIP-Client/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                ip = resp.read().decode("utf-8").strip()
                if ip and "." in ip and len(ip) <= 15:
                    return ip
        except Exception:
            continue
    return None


class DDNSUpdaterCore:
    """Hem GUI hem de arka plan servisi (daemon) tarafından kullanılan DDNS istemci çekirdeği."""

    def __init__(self, on_log: Optional[Callable[[str], None]] = None, on_state_change: Optional[Callable[[], None]] = None):
        self.config = load_config()
        self.on_log = on_log
        self.on_state_change = on_state_change

        self.last_ip: str = "—"
        self.last_fqdns: List[str] = []
        self.last_status: str = "Bekleniyor"
        self.last_update_time: str = "Henüz güncellenmedi"
        self.is_healthy: Optional[bool] = None
        self.next_run_timestamp: float = 0.0

        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

    def log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}"
        if self.on_log:
            try:
                self.on_log(line)
            except Exception:
                pass
        else:
            print(line, flush=True)

    def notify_state(self) -> None:
        if self.on_state_change:
            try:
                self.on_state_change()
            except Exception:
                pass

    def start_background_loop(self) -> None:
        if self._worker_thread and self._worker_thread.is_alive():
            return
        self._stop_event.clear()
        self._worker_thread = threading.Thread(target=self._loop, name="DDNS-Updater-Loop", daemon=True)
        self._worker_thread.start()

    def stop_background_loop(self) -> None:
        self._stop_event.set()
        self._wake_event.set()

    def trigger_immediate_update(self) -> None:
        self._wake_event.set()

    def _loop(self) -> None:
        self.log(f"Arka plan DDNS servisi başlatıldı ({get_client_device_info()}).")
        while not self._stop_event.is_set():
            if self.config.get("auto_sync_enabled", True) and self.config.get("api_token", "").strip():
                self.perform_update()
            interval_sec = max(30, int(self.config.get("interval_minutes", 5) or 5) * 60)
            self.next_run_timestamp = time.time() + interval_sec
            self.notify_state()
            self._wake_event.wait(timeout=interval_sec)
            self._wake_event.clear()

    def perform_update(self) -> Tuple[bool, str]:
        server_url = self.config.get("server_url", "").strip().rstrip("/")
        token = self.config.get("api_token", "").strip()
        subs_raw = self.config.get("subdomains", "").strip()

        if not server_url or not token or not subs_raw:
            self.is_healthy = False
            self.last_status = "Eksik Ayar (Token / Alan Adı girin)"
            self.notify_state()
            return False, self.last_status

        subdomains = [s.strip().lower() for s in subs_raw.split(",") if s.strip()]
        external_ip = ""
        if self.config.get("auto_detect_external_ip", True):
            detected = fetch_external_ipv4()
            if detected:
                external_ip = detected

        # 1. Önce DNSIP JSON API v1 uç noktasını dene (/api/v1/update)
        api_url = f"{server_url}/api/v1/update"
        payload = json.dumps(
            {
                "domains": subdomains,
                "ipv4": external_ip,
                "client_info": get_client_device_info(),
                "auto_create": True,
            }
        ).encode("utf-8")

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": f"DNSIP-Desktop ({get_client_device_info()})",
        }

        try:
            req = urllib.request.Request(api_url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=12) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))

            if resp_data.get("ok"):
                results = resp_data.get("results", [])
                self.last_fqdns = [r.get("fqdn", r.get("subdomain", "")) for r in results]
                first_ip = results[0].get("ipv4") if results else resp_data.get("detected_ip", external_ip)
                statuses = [r.get("status", "OK") for r in results]
                self.last_ip = first_ip or external_ip or "Algılandı"
                self.last_update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.is_healthy = True
                status_summary = "UPDATED" if "UPDATED" in statuses else "NOCHANGE"
                self.last_status = f"Aktif ({status_summary})"
                fqdn_str = ", ".join(self.last_fqdns)
                self.log(f"✅ Güncelleme başarılı: {fqdn_str} -> {self.last_ip} [{status_summary}]")
                self.notify_state()
                return True, f"{fqdn_str} -> {self.last_ip}"
            else:
                err_msg = resp_data.get("error", "Bilinmeyen sunucu hatası")
                raise RuntimeError(err_msg)

        except urllib.error.HTTPError as http_err:
            # Eğer sunucu standart DuckDNS (/update) protokolü bekliyorsa yedek olarak onu dene
            if http_err.code == 404:
                return self._fallback_duckdns_protocol(server_url, token, subdomains, external_ip)
            err_body = ""
            try:
                err_body = http_err.read().decode("utf-8")
                err_json = json.loads(err_body)
                err_body = err_json.get("error", err_body)
            except Exception:
                pass
            msg = f"HTTP {http_err.code}: {err_body or http_err.reason}"
            self.is_healthy = False
            self.last_status = f"Hata ({msg})"
            self.log(f"❌ Sunucu hatası: {msg}")
            self.notify_state()
            return False, msg

        except Exception as exc:
            msg = str(exc)
            self.is_healthy = False
            self.last_status = "Bağlantı Hatası"
            self.log(f"❌ Bağlantı kurulamadı ({server_url}): {msg}")
            self.notify_state()
            return False, msg

    def _fallback_duckdns_protocol(
        self, server_url: str, token: str, subdomains: List[str], external_ip: str
    ) -> Tuple[bool, str]:
        params = urllib.parse.urlencode(
            {
                "domains": ",".join(subdomains),
                "token": token,
                "ip": external_ip,
                "verbose": "true",
            }
        )
        url = f"{server_url}/update?{params}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": f"DNSIP-Desktop ({get_client_device_info()})"})
            with urllib.request.urlopen(req, timeout=12) as resp:
                text = resp.read().decode("utf-8").strip()
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            if lines and lines[0] == "OK":
                ip_used = lines[1] if len(lines) > 1 else (external_ip or "Otomatik")
                state = lines[-1] if len(lines) > 2 else "OK"
                self.last_ip = ip_used
                self.last_fqdns = subdomains
                self.last_update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.is_healthy = True
                self.last_status = f"Aktif ({state})"
                self.log(f"✅ DuckDNS protokolü ile güncellendi: {','.join(subdomains)} -> {ip_used}")
                self.notify_state()
                return True, f"OK ({ip_used})"
            else:
                self.is_healthy = False
                self.last_status = "Hata (KO - Token veya Domain geçersiz)"
                self.log("❌ Sunucu 'KO' yanıtı döndü. Token veya alt alan adını kontrol edin.")
                self.notify_state()
                return False, "KO (Yetki veya alan adı hatası)"
        except Exception as exc:
            self.is_healthy = False
            self.last_status = f"Hata: {exc}"
            self.notify_state()
            return False, str(exc)

    def fetch_Remote_domains(self) -> Tuple[bool, str, List[Dict], str]:
        """Sunucudaki mevcut kayıtlı alt alan adlarını getirir."""
        server_url = self.config.get("server_url", "").strip().rstrip("/")
        token = self.config.get("api_token", "").strip()
        if not server_url or not token:
            return False, "Önce Sunucu Adresi ve API Token alanlarını doldurun.", [], ""

        url = f"{server_url}/api/v1/domains"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if data.get("ok"):
                return True, "Başarılı", data.get("domains", []), data.get("base_domain", "")
            return False, data.get("error", "Bilinmeyen hata"), [], ""
        except Exception as exc:
            return False, f"Sunucudan alan adları alınamadı: {exc}", [], ""


# =====================================================================
# GÖRSEL MASAÜSTÜ ARAYÜZÜ (GUI) + SİSTEM TEPSİSİ (WINDOWS & macOS)
# =====================================================================


def run_gui_app(start_minimized: bool = False) -> None:
    import tkinter as tk
    from tkinter import messagebox, ttk

    # Opsiyonel Sistem Tepsisi (pystray + Pillow) kontrolü
    HAS_TRAY = False
    try:
        import pystray
        from PIL import Image, ImageDraw

        HAS_TRAY = True
    except ImportError:
        HAS_TRAY = False

    root = tk.Tk()
    root.title("DNSIP — Dinamik DNS İstemcisi (Windows & macOS)")
    root.geometry("680x640")
    root.minsize(640, 590)
    root.configure(bg="#0f172a")

    # Renk Paleti
    BG_DARK = "#0f172a"
    BG_CARD = "#1e293b"
    BORDER = "#334155"
    TEXT_MAIN = "#f8fafc"
    TEXT_MUTED = "#94a3b8"
    ACCENT = "#38bdf8"
    OK_COLOR = "#22c55e"
    ERR_COLOR = "#ef4444"
    WARN_COLOR = "#f59e0b"

    core = DDNSUpdaterCore()
    tray_icon_ref = {"icon": None}

    def create_tray_image(color_hex: str):
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.ellipse((6, 6, 58, 58), fill="#1e293b", outline=color_hex, width=5)
        draw.ellipse((20, 20, 44, 44), fill=color_hex)
        return img

    # --- UI Değişkenleri ---
    var_server = tk.StringVar(value=core.config.get("server_url", "http://127.0.0.1:8080"))
    var_token = tk.StringVar(value=core.config.get("api_token", ""))
    var_subdomains = tk.StringVar(value=core.config.get("subdomains", "ev"))
    var_interval = tk.StringVar(value=str(core.config.get("interval_minutes", 5)))
    var_ext_ip = tk.BooleanVar(value=bool(core.config.get("auto_detect_external_ip", True)))
    var_autostart = tk.BooleanVar(value=is_autostart_enabled())

    var_status_text = tk.StringVar(value="Durum: Bekleniyor")
    var_current_ip = tk.StringVar(value="Mevcut Dış IP: —")
    var_bound_fqdn = tk.StringVar(value="Bağlı Alan Adı: —")
    var_last_time = tk.StringVar(value="Son Güncelleme: —")

    # --- Üst Başlık ---
    header_frame = tk.Frame(root, bg="#0b1120", pady=14, padx=20)
    header_frame.pack(fill="x")

    title_lbl = tk.Label(
        header_frame,
        text="🌐 DNSIP Masaüstü İstemcisi",
        font=("Segoe UI", 15, "bold"),
        fg=TEXT_MAIN,
        bg="#0b1120",
    )
    title_lbl.pack(side="left")

    status_badge = tk.Label(
        header_frame,
        textvariable=var_status_text,
        font=("Segoe UI", 10, "bold"),
        fg=WARN_COLOR,
        bg="#1e293b",
        padx=12,
        pady=5,
    )
    status_badge.pack(side="right")

    # --- Ana İçerik Çerçevesi ---
    main_frame = tk.Frame(root, bg=BG_DARK, padx=20, pady=12)
    main_frame.pack(fill="both", expand=True)

    # 1. CANLI DURUM KARTI
    status_card = tk.Frame(main_frame, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1, padx=16, pady=12)
    status_card.pack(fill="x", pady=(0, 12))

    info_left = tk.Frame(status_card, bg=BG_CARD)
    info_left.pack(side="left", fill="x", expand=True)

    tk.Label(info_left, textvariable=var_bound_fqdn, font=("Segoe UI", 12, "bold"), fg=ACCENT, bg=BG_CARD, anchor="w").pack(fill="x")
    tk.Label(info_left, textvariable=var_current_ip, font=("Segoe UI", 11), fg=TEXT_MAIN, bg=BG_CARD, anchor="w").pack(fill="x", pady=2)
    tk.Label(info_left, textvariable=var_last_time, font=("Segoe UI", 9), fg=TEXT_MUTED, bg=BG_CARD, anchor="w").pack(fill="x")

    btn_frame_right = tk.Frame(status_card, bg=BG_CARD)
    btn_frame_right.pack(side="right")

    def on_sync_now():
        save_current_ui_to_config(silent=True)
        status_badge.config(fg=WARN_COLOR)
        var_status_text.set("Durum: Güncelleniyor...")
        threading.Thread(target=core.perform_update, daemon=True).start()

    def on_open_web_panel():
        url = var_server.get().strip()
        if url:
            webbrowser.open(url)

    btn_sync_now = tk.Button(
        btn_frame_right,
        text="🔄 Şimdi Güncelle",
        font=("Segoe UI", 10, "bold"),
        bg=ACCENT,
        fg="#0f172a",
        activebackground="#0284c7",
        activeforeground="#ffffff",
        relief="flat",
        padx=14,
        pady=7,
        cursor="hand2",
        command=on_sync_now,
    )
    btn_sync_now.pack(side="top", fill="x", pady=(0, 6))

    btn_web = tk.Button(
        btn_frame_right,
        text="🌍 Web Panelini Aç",
        font=("Segoe UI", 9),
        bg="#334155",
        fg=TEXT_MAIN,
        activebackground="#475569",
        activeforeground="#ffffff",
        relief="flat",
        padx=12,
        pady=5,
        cursor="hand2",
        command=on_open_web_panel,
    )
    btn_web.pack(side="top", fill="x")

    # 2. BAĞLANTI VE ALAN ADI AYARLARI KARTI
    cfg_card = tk.Frame(main_frame, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1, padx=16, pady=14)
    cfg_card.pack(fill="x", pady=(0, 12))

    tk.Label(cfg_card, text="⚙️ Sunucu ve Alan Adı Bağlantı Ayarları", font=("Segoe UI", 11, "bold"), fg=TEXT_MAIN, bg=BG_CARD).grid(
        row=0, column=0, columnspan=3, sticky="w", pady=(0, 10)
    )

    tk.Label(cfg_card, text="Sunucu Adresi (URL):", font=("Segoe UI", 10), fg=TEXT_MUTED, bg=BG_CARD).grid(row=1, column=0, sticky="w", pady=5)
    entry_server = tk.Entry(cfg_card, textvariable=var_server, font=("Segoe UI", 10), bg="#0f172a", fg=TEXT_MAIN, insertbackground=TEXT_MAIN, relief="flat", highlightbackground=BORDER, highlightthickness=1)
    entry_server.grid(row=1, column=1, columnspan=2, sticky="ew", padx=(10, 0), pady=5, ipady=5)

    tk.Label(cfg_card, text="API Token Anahtarı:", font=("Segoe UI", 10), fg=TEXT_MUTED, bg=BG_CARD).grid(row=2, column=0, sticky="w", pady=5)
    entry_token = tk.Entry(cfg_card, textvariable=var_token, font=("Segoe UI", 10), bg="#0f172a", fg=ACCENT, insertbackground=TEXT_MAIN, relief="flat", highlightbackground=BORDER, highlightthickness=1)
    entry_token.grid(row=2, column=1, columnspan=2, sticky="ew", padx=(10, 0), pady=5, ipady=5)

    tk.Label(cfg_card, text="Alt Alan Adı (Subdomain):", font=("Segoe UI", 10), fg=TEXT_MUTED, bg=BG_CARD).grid(row=3, column=0, sticky="w", pady=5)
    entry_subs = tk.Entry(cfg_card, textvariable=var_subdomains, font=("Segoe UI", 10), bg="#0f172a", fg=TEXT_MAIN, insertbackground=TEXT_MAIN, relief="flat", highlightbackground=BORDER, highlightthickness=1)
    entry_subs.grid(row=3, column=1, sticky="ew", padx=(10, 8), pady=5, ipady=5)

    def on_fetch_domains():
        save_current_ui_to_config(silent=True)
        ok, msg, doms, base_dom = core.fetch_Remote_domains()
        if not ok:
            messagebox.showwarning("Sunucu Bağlantısı", msg)
            return
        if not doms:
            messagebox.showinfo(
                "Bilgi",
                f"Sunucuda ({base_dom}) henüz kayıtlı alt alan adı yok.\n"
                "Alt Alan Adı kutusuna istediğiniz adı (örn: ev) yazıp 'Ayarları Kaydet & Güncelle' butonuna basarsanız otomatik oluşturulur.",
            )
            return
        sub_list = ",".join(d["subdomain"] for d in doms)
        var_subdomains.set(sub_list)
        core.log(f"📥 Sunucudan kayıtlı alan adları çekildi: {sub_list}.{base_dom}")

    btn_fetch = tk.Button(
        cfg_card,
        text="📥 Sunucudan Getir",
        font=("Segoe UI", 9),
        bg="#334155",
        fg=TEXT_MAIN,
        relief="flat",
        padx=10,
        pady=5,
        cursor="hand2",
        command=on_fetch_domains,
    )
    btn_fetch.grid(row=3, column=2, sticky="ew", pady=5)

    tk.Label(cfg_card, text="Kontrol Sıklığı (Dakika):", font=("Segoe UI", 10), fg=TEXT_MUTED, bg=BG_CARD).grid(row=4, column=0, sticky="w", pady=5)
    spin_interval = tk.Spinbox(cfg_card, from_=1, to=120, textvariable=var_interval, width=8, font=("Segoe UI", 10), bg="#0f172a", fg=TEXT_MAIN, buttonbackground="#334155", relief="flat", highlightbackground=BORDER, highlightthickness=1)
    spin_interval.grid(row=4, column=1, sticky="w", padx=(10, 0), pady=5, ipady=3)

    cfg_card.columnconfigure(1, weight=1)

    # Onay Kutuları (Dış IP algılama & Otomatik Başlatma)
    chk_ext = tk.Checkbutton(
        cfg_card,
        text="Dış IP adresimi harici servislerden (ipify/icanhazip) otomatik doğrula",
        variable=var_ext_ip,
        font=("Segoe UI", 9),
        fg=TEXT_MAIN,
        bg=BG_CARD,
        selectcolor="#0f172a",
        activebackground=BG_CARD,
        activeforeground=TEXT_MAIN,
    )
    chk_ext.grid(row=5, column=0, columnspan=3, sticky="w", pady=(6, 2))

    def on_toggle_autostart():
        enabled = var_autostart.get()
        ok, msg = set_autostart(enabled)
        core.log(f"{'✅' if ok else '⚠️'} {msg}")
        if not ok:
            messagebox.showwarning("Otomatik Başlatma", msg)

    chk_autostart = tk.Checkbutton(
        cfg_card,
        text="Bilgisayar açıldığında arka planda (Sistem Tepsisinde) otomatik başlat",
        variable=var_autostart,
        font=("Segoe UI", 9),
        fg=TEXT_MAIN,
        bg=BG_CARD,
        selectcolor="#0f172a",
        activebackground=BG_CARD,
        activeforeground=TEXT_MAIN,
        command=on_toggle_autostart,
    )
    chk_autostart.grid(row=6, column=0, columnspan=3, sticky="w", pady=2)

    def save_current_ui_to_config(silent: bool = False):
        try:
            iv = max(1, int(var_interval.get().strip() or 5))
        except ValueError:
            iv = 5
        new_cfg = {
            "server_url": var_server.get().strip().rstrip("/"),
            "api_token": var_token.get().strip(),
            "subdomains": var_subdomains.get().strip(),
            "interval_minutes": iv,
            "auto_detect_external_ip": bool(var_ext_ip.get()),
            "auto_sync_enabled": True,
        }
        core.config = new_cfg
        save_config(new_cfg)
        if not silent:
            core.log("💾 Ayarlar kaydedildi ve senkronizasyon tetiklendi.")
            core.trigger_immediate_update()

    btn_save = tk.Button(
        cfg_card,
        text="💾 Ayarları Kaydet & Şimdi Eşitle",
        font=("Segoe UI", 10, "bold"),
        bg="#22c55e",
        fg="#0f172a",
        activebackground="#16a34a",
        activeforeground="#ffffff",
        relief="flat",
        pady=7,
        cursor="hand2",
        command=lambda: save_current_ui_to_config(silent=False),
    )
    btn_save.grid(row=7, column=0, columnspan=3, sticky="ew", pady=(10, 0))

    # 3. CANLI LOG EKRANI
    log_card = tk.Frame(main_frame, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1, padx=14, pady=10)
    log_card.pack(fill="both", expand=True)

    tk.Label(log_card, text="📜 Canlı İşlem Günlüğü (Log)", font=("Segoe UI", 10, "bold"), fg=TEXT_MAIN, bg=BG_CARD).pack(anchor="w", pady=(0, 6))

    log_text = tk.Text(
        log_card,
        height=7,
        bg="#0b1120",
        fg="#cbd5e1",
        font=("Consolas", 9),
        relief="flat",
        state="disabled",
        padx=8,
        pady=8,
    )
    log_text.pack(fill="both", expand=True)

    def append_log_safe(line: str):
        def _do():
            log_text.config(state="normal")
            log_text.insert("end", line + "\n")
            log_text.see("end")
            log_text.config(state="disabled")

        root.after(0, _do)

    def refresh_ui_state_safe():
        def _do():
            var_status_text.set(f"● {core.last_status}")
            var_current_ip.set(f"Mevcut Dış IP Adresiniz: {core.last_ip}")
            fqdn_display = ", ".join(core.last_fqdns) if core.last_fqdns else var_subdomains.get()
            var_bound_fqdn.set(f"Bağlı Alan Adı: {fqdn_display}")
            var_last_time.set(f"Son Kontrol: {core.last_update_time}")

            if core.is_healthy is True:
                status_badge.config(fg=OK_COLOR)
                if HAS_TRAY and tray_icon_ref["icon"]:
                    tray_icon_ref["icon"].icon = create_tray_image(OK_COLOR)
            elif core.is_healthy is False:
                status_badge.config(fg=ERR_COLOR)
                if HAS_TRAY and tray_icon_ref["icon"]:
                    tray_icon_ref["icon"].icon = create_tray_image(ERR_COLOR)
            else:
                status_badge.config(fg=WARN_COLOR)

        root.after(0, _do)

    core.on_log = append_log_safe
    core.on_state_change = refresh_ui_state_safe

    # --- Sistem Tepsisi (System Tray / macOS Menu Bar) Yönetimi ---
    def show_window():
        root.after(0, lambda: (root.deiconify(), root.lift(), root.focus_force()))

    def hide_window_to_tray():
        if HAS_TRAY and tray_icon_ref["icon"]:
            root.withdraw()
            core.log("🔽 Uygulama sistem tepsisinde (arka planda) çalışmaya devam ediyor.")
        else:
            root.iconify()

    def quit_app():
        core.stop_background_loop()
        if HAS_TRAY and tray_icon_ref["icon"]:
            try:
                tray_icon_ref["icon"].stop()
            except Exception:
                pass
        root.after(0, root.destroy)

    root.protocol("WM_DELETE_WINDOW", hide_window_to_tray)

    if HAS_TRAY:
        menu = pystray.Menu(
            pystray.MenuItem("🎛️ Kontrol Panelini Aç", lambda icon, item: show_window(), default=True),
            pystray.MenuItem("🔄 Şimdi Güncelle", lambda icon, item: on_sync_now()),
            pystray.MenuItem("🌍 Web Panelini Tarayıcıda Aç", lambda icon, item: on_open_web_panel()),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("❌ Tamamen Çıkış Yap", lambda icon, item: quit_app()),
        )
        tray_icon = pystray.Icon("dnsip_client", create_tray_image(WARN_COLOR), "DNSIP Dinamik DNS", menu)
        tray_icon_ref["icon"] = tray_icon
        try:
            # run_detached hem Windows hem macOS'ta tkinter ana döngüsüyle uyumlu çalışır
            tray_icon.run_detached()
        except Exception:
            threading.Thread(target=tray_icon.run, daemon=True).start()
    else:
        core.log("ℹ️ Not: Sistem tepsisi ikonu için 'pip install pystray Pillow' kurabilirsiniz.")

    if start_minimized:
        root.withdraw()

    core.start_background_loop()
    root.mainloop()


def run_daemon_cli() -> None:
    """Görsel arayüz olmadan (Headless / Servis modunda) çalıştırır."""
    core = DDNSUpdaterCore()
    core.log("DNSIP Headless Daemon modu başlatıldı. Çıkmak için Ctrl+C basın.")
    core.start_background_loop()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        core.stop_background_loop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNSIP Dinamik DNS Masaüstü İstemcisi (Windows & macOS)")
    parser.add_argument("--minimized", action="store_true", help="Uygulamayı doğrudan sistem tepsisinde (gizli) başlatır")
    parser.add_argument("--daemon", action="store_true", help="Arayüz (GUI) olmadan arka plan servisi olarak çalıştırır")
    parser.add_argument("--server", type=str, help="Sunucu URL adresini yapılandırır (Örn: http://1.2.3.4:8080)")
    parser.add_argument("--token", type=str, help="API Token anahtarını yapılandırır")
    parser.add_argument("--domains", type=str, help="Alt alan adlarını yapılandırır (Örn: ev,macbook)")
    args = parser.parse_args()

    if args.server or args.token or args.domains:
        cfg = load_config()
        if args.server:
            cfg["server_url"] = args.server.strip().rstrip("/")
        if args.token:
            cfg["api_token"] = args.token.strip()
        if args.domains:
            cfg["subdomains"] = args.domains.strip()
        save_config(cfg)

    if args.daemon:
        run_daemon_cli()
    else:
        run_gui_app(start_minimized=args.minimized)
