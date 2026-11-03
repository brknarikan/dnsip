import base64
import html
import http.cookies
import ipaddress
import json
import logging
import os
import secrets
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional, Tuple

from database import (
    create_domain,
    delete_domain,
    get_recent_logs,
    get_settings,
    get_user_by_id,
    get_user_by_token,
    get_user_by_username,
    init_db,
    list_domains,
    regenerate_user_token,
    update_domain_record,
    update_settings,
    update_user_credentials,
    verify_password,
)
from dns_engine import PurePythonDNSServer, sync_to_cloudflare

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("dnsip.server")

# Aktif web oturumları: {session_token: user_id}
SESSIONS: Dict[str, int] = {}
DNS_SERVER_INSTANCE: Optional[PurePythonDNSServer] = None
DNS_SERVER_STATUS: Tuple[bool, str] = (False, "Başlatılmadı")


def detect_client_ip(handler: BaseHTTPRequestHandler) -> str:
    """
    Reverse proxy (Nginx, Caddy, Cloudflare) arkasında veya doğrudan bağlantıda
    istemcinin gerçek dış IP adresini tespit eder.
    """
    for header in ("CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"):
        val = handler.headers.get(header)
        if val:
            first_ip = val.split(",")[0].strip()
            if first_ip:
                return first_ip
    client_host = handler.client_address[0]
    # IPv4-mapped IPv6 adresini temizle (::ffff:192.168.1.1 -> 192.168.1.1)
    if client_host.startswith("::ffff:"):
        client_host = client_host[7:]
    return client_host


def validate_ip(ip_str: str) -> Tuple[Optional[str], Optional[str]]:
    """Verilen IP dizgesini doğrular ve (ipv4, ipv6) olarak döner."""
    if not ip_str:
        return None, None
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        if isinstance(addr, ipaddress.IPv4Address):
            return str(addr), None
        return None, str(addr)
    except ValueError:
        return None, None


class DNSIPHTTPHandler(BaseHTTPRequestHandler):
    server_version = "DNSIP-Server/1.0"

    def log_message(self, fmt: str, *args) -> None:
        logger.info("%s - %s", detect_client_ip(self), fmt % args)

    def _send_json(self, status: int, data: Dict) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status: int, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status: int, html_content: str, cookie_header: Optional[str] = None) -> None:
        body = html_content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if cookie_header:
            self.send_header("Set-Cookie", cookie_header)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str, cookie_header: Optional[str] = None) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        if cookie_header:
            self.send_header("Set-Cookie", cookie_header)
        self.end_headers()

    def _get_session_user(self) -> Optional[Dict]:
        cookie_raw = self.headers.get("Cookie", "")
        cookie = http.cookies.SimpleCookie()
        try:
            cookie.load(cookie_raw)
        except Exception:
            return None
        if "dnsip_session" in cookie:
            sid = cookie["dnsip_session"].value
            uid = SESSIONS.get(sid)
            if uid:
                return get_user_by_id(uid)
        return None

    def _get_api_user(self, query_params: Dict[str, list]) -> Optional[Dict]:
        # 1. Authorization: Bearer <token> veya Basic Auth
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return get_user_by_token(auth[7:].strip())
        if auth.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth[6:].strip()).decode("utf-8")
                _, pwd_or_token = decoded.split(":", 1)
                return get_user_by_token(pwd_or_token)
            except Exception:
                pass
        # 2. X-API-Token header
        x_token = self.headers.get("X-API-Token", "")
        if x_token:
            return get_user_by_token(x_token)
        # 3. Query string ?token=...
        if "token" in query_params and query_params["token"]:
            return get_user_by_token(query_params["token"][0])
        return None

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0:
            return b""
        return self.rfile.read(min(length, 1024 * 1024))

    # --- HTTP METOTLARI ---

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Token")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qparams = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        # 1. Orijinal DuckDNS Uyumlu Endpoint (/update)
        if path == "/update":
            self._handle_duckdns_update(qparams)
            return

        # 2. DynDNS2 / Modem Uyumlu Endpoint (/nic/update)
        if path == "/nic/update":
            self._handle_dyndns_update(qparams)
            return

        # 3. JSON API v1
        if path == "/api/v1/status":
            settings = get_settings()
            self._send_json(
                200,
                {
                    "ok": True,
                    "service": "DNSIP Dynamic DNS Server",
                    "base_domain": settings.get("base_domain", ""),
                    "detected_ip": detect_client_ip(self),
                    "dns_engine_active": DNS_SERVER_STATUS[0],
                    "dns_engine_message": DNS_SERVER_STATUS[1],
                },
            )
            return

        if path == "/api/v1/domains":
            user = self._get_api_user(qparams)
            if not user:
                self._send_json(401, {"ok": False, "error": "Geçersiz veya eksik API Token."})
                return
            settings = get_settings()
            base_domain = settings.get("base_domain", "")
            domains = list_domains(user["id"])
            for d in domains:
                d["fqdn"] = f"{d['subdomain']}.{base_domain}"
            self._send_json(
                200,
                {
                    "ok": True,
                    "base_domain": base_domain,
                    "detected_ip": detect_client_ip(self),
                    "domains": domains,
                },
            )
            return

        # 4. Web Paneli Rotaları
        if path == "/login":
            if self._get_session_user():
                self._redirect("/")
                return
            self._render_login()
            return

        if path == "/logout":
            cookie_raw = self.headers.get("Cookie", "")
            cookie = http.cookies.SimpleCookie()
            try:
                cookie.load(cookie_raw)
                if "dnsip_session" in cookie:
                    SESSIONS.pop(cookie["dnsip_session"].value, None)
            except Exception:
                pass
            self._redirect("/login", "dnsip_session=; Path=/; Max-Age=0; HttpOnly")
            return

        if path == "/":
            user = self._get_session_user()
            if not user:
                self._redirect("/login")
                return
            msg = qparams.get("msg", [""])[0]
            err = qparams.get("err", [""])[0]
            self._render_dashboard(user, msg=msg, err=err)
            return

        self._send_text(404, "404 Not Found")

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qparams = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        raw_body = self._read_body()

        # JSON API v1 POST uç noktaları
        if path.startswith("/api/v1/"):
            user = self._get_api_user(qparams)
            if not user:
                self._send_json(401, {"ok": False, "error": "Geçersiz veya eksik API Token."})
                return
            try:
                payload = json.loads(raw_body.decode("utf-8") or "{}")
            except Exception:
                self._send_json(400, {"ok": False, "error": "Geçersiz JSON verisi."})
                return

            if path == "/api/v1/update":
                self._handle_api_v1_update(user, payload)
                return

            if path == "/api/v1/domains":
                sub = str(payload.get("subdomain", "")).strip().lower()
                base_domain = get_settings().get("base_domain", "")
                if sub.endswith("." + base_domain):
                    sub = sub[: -(len(base_domain) + 1)]
                ipv4 = str(payload.get("ipv4", "")).strip() or detect_client_ip(self)
                ok, message = create_domain(user["id"], sub, ipv4=ipv4)
                if ok:
                    sync_to_cloudflare(sub, ipv4=ipv4)
                self._send_json(200 if ok else 400, {"ok": ok, "message": message, "subdomain": sub, "ipv4": ipv4})
                return

        # Web Paneli POST İşlemleri
        form_data = urllib.parse.parse_qs(raw_body.decode("utf-8", errors="ignore"), keep_blank_values=True)
        get_field = lambda k, default="": form_data.get(k, [default])[0].strip()

        if path == "/login":
            username = get_field("username")
            password = get_field("password")
            user = get_user_by_username(username)
            if user and verify_password(password, user["password_hash"]):
                sid = secrets.token_urlsafe(32)
                SESSIONS[sid] = user["id"]
                self._redirect("/", f"dnsip_session={sid}; Path=/; HttpOnly; SameSite=Lax")
            else:
                self._render_login("Kullanıcı adı veya şifre hatalı!")
            return

        user = self._get_session_user()
        if not user:
            self._redirect("/login")
            return

        if path == "/panel/domain/create":
            sub = get_field("subdomain").lower()
            base_domain = get_settings().get("base_domain", "").lower()
            if sub.endswith("." + base_domain):
                sub = sub[: -(len(base_domain) + 1)]
            ip = get_field("ipv4") or detect_client_ip(self)
            ok, message = create_domain(user["id"], sub, ipv4=ip)
            if ok:
                sync_to_cloudflare(sub, ipv4=ip)
                self._redirect("/?msg=" + urllib.parse.quote(message))
            else:
                self._redirect("/?err=" + urllib.parse.quote(message))
            return

        if path == "/panel/domain/update":
            sub = get_field("subdomain").lower()
            ipv4 = get_field("ipv4")
            ipv6 = get_field("ipv6")
            txt = get_field("txt_record")
            ok, status_str, _ = update_domain_record(
                user["id"],
                sub,
                ipv4=ipv4,
                ipv6=ipv6,
                txt_record=txt,
                client_info="Web Panel (Manuel)",
            )
            if ok:
                sync_to_cloudflare(sub, ipv4=ipv4, ipv6=ipv6, txt=txt)
                self._redirect("/?msg=" + urllib.parse.quote(f"'{sub}' kaydı güncellendi ({status_str})."))
            else:
                self._redirect("/?err=" + urllib.parse.quote(f"Güncelleme başarısız: {status_str}"))
            return

        if path == "/panel/domain/delete":
            sub = get_field("subdomain").lower()
            delete_domain(user["id"], sub, is_admin=bool(user["is_admin"]))
            self._redirect("/?msg=" + urllib.parse.quote(f"'{sub}' alt alan adı silindi."))
            return

        if path == "/panel/token/regenerate":
            regenerate_user_token(user["id"])
            self._redirect("/?msg=" + urllib.parse.quote("API Token başarıyla yenilendi."))
            return

        if path == "/panel/settings":
            new_cfg = {
                "base_domain": get_field("base_domain", "ornekalanadi.com").lower().strip("."),
                "ns1_host": get_field("ns1_host", "ns1.ornekalanadi.com").lower().strip("."),
                "ns2_host": get_field("ns2_host", "ns2.ornekalanadi.com").lower().strip("."),
                "server_public_ip": get_field("server_public_ip", "127.0.0.1"),
                "default_ttl": get_field("default_ttl", "60"),
                "cf_enabled": "1" if get_field("cf_enabled") == "1" else "0",
                "cf_api_token": get_field("cf_api_token"),
                "cf_zone_id": get_field("cf_zone_id"),
            }
            update_settings(new_cfg)
            self._redirect("/?msg=" + urllib.parse.quote("Sunucu ve DNS ayarları kaydedildi."))
            return

        if path == "/panel/account":
            new_username = get_field("username", user["username"])
            new_password = get_field("new_password")
            update_user_credentials(user["id"], new_username, new_password if new_password else None)
            self._redirect("/?msg=" + urllib.parse.quote("Hesap bilgileri güncellendi."))
            return

        self._send_text(404, "404 Not Found")

    def do_DELETE(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        qparams = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        if path.startswith("/api/v1/domains/"):
            user = self._get_api_user(qparams)
            if not user:
                self._send_json(401, {"ok": False, "error": "Yetkisiz erişim."})
                return
            sub = path.split("/api/v1/domains/", 1)[1].strip().lower()
            deleted = delete_domain(user["id"], sub, is_admin=bool(user["is_admin"]))
            self._send_json(200 if deleted else 404, {"ok": deleted, "subdomain": sub})
            return

        self._send_json(404, {"ok": False, "error": "Uç nokta bulunamadı."})

    # --- DUCKDNS & API GÜNCELLEME İŞLEYİCİLERİ ---

    def _handle_duckdns_update(self, qparams: Dict[str, list]) -> None:
        """
        Orijinal DuckDNS HTTP GET spesifikasyonu:
        /update?domains=ev,ofis&token=TOKEN&ip=1.2.3.4&ipv6=&txt=&verbose=true&clear=false
        """
        domains_raw = qparams.get("domains", [""])[0]
        token = qparams.get("token", [""])[0]
        ip_param = qparams.get("ip", [""])[0].strip()
        ipv6_param = qparams.get("ipv6", [""])[0].strip()
        txt_param = qparams.get("txt", [None])[0]
        verbose = qparams.get("verbose", ["false"])[0].lower() == "true"
        clear = qparams.get("clear", ["false"])[0].lower() == "true"

        user = get_user_by_token(token)
        if not user or not domains_raw:
            self._send_text(200, "KO")
            return

        settings = get_settings()
        base_domain = settings.get("base_domain", "").lower()

        # IP boş bırakıldıysa isteği gönderenin dış IP adresini otomatik kullan
        detected = detect_client_ip(self)
        ipv4_val, ipv6_val = None, None

        if ip_param:
            v4, v6 = validate_ip(ip_param)
            if not v4 and not v6:
                self._send_text(200, "KO")
                return
            ipv4_val, ipv6_val = v4, v6
        elif txt_param is None and not clear:
            v4, v6 = validate_ip(detected)
            ipv4_val, ipv6_val = v4, v6

        if ipv6_param:
            _, v6 = validate_ip(ipv6_param)
            if not v6:
                self._send_text(200, "KO")
                return
            ipv6_val = v6

        user_agent = self.headers.get("User-Agent", "DuckDNS-Client")[:80]
        subdomains = [d.strip().lower() for d in domains_raw.split(",") if d.strip()]
        if not subdomains:
            self._send_text(200, "KO")
            return

        overall_status = "NOCHANGE"
        for sub in subdomains:
            if base_domain and sub.endswith("." + base_domain):
                sub = sub[: -(len(base_domain) + 1)]
            ok, st, rec = update_domain_record(
                user["id"],
                sub,
                ipv4=ipv4_val,
                ipv6=ipv6_val,
                txt_record=txt_param,
                clear_txt=clear,
                client_info=user_agent,
                auto_create=True,
            )
            if not ok:
                self._send_text(200, "KO")
                return
            if st == "UPDATED":
                overall_status = "UPDATED"
            sync_to_cloudflare(sub, ipv4=rec.get("ipv4", ""), ipv6=rec.get("ipv6", ""), txt=rec.get("txt_record", ""))

        if verbose:
            lines = [
                "OK",
                ipv4_val or "",
                ipv6_val or "",
                overall_status,
            ]
            self._send_text(200, "\n".join(lines))
        else:
            self._send_text(200, "OK")

    def _handle_dyndns_update(self, qparams: Dict[str, list]) -> None:
        """Modem / Router (Keenetic, Asus, OpenWrt, pfSense) standart DynDNS2 protokolü."""
        user = self._get_api_user(qparams)
        if not user:
            self._send_text(401, "badauth")
            return

        hostname_raw = qparams.get("hostname", [""])[0]
        myip = qparams.get("myip", [""])[0].strip() or detect_client_ip(self)
        v4, v6 = validate_ip(myip)
        if not v4 and not v6:
            self._send_text(200, "dnserr")
            return

        base_domain = get_settings().get("base_domain", "").lower()
        sub = hostname_raw.split(",")[0].strip().lower()
        if base_domain and sub.endswith("." + base_domain):
            sub = sub[: -(len(base_domain) + 1)]

        ok, st, rec = update_domain_record(
            user["id"],
            sub,
            ipv4=v4,
            ipv6=v6,
            client_info=self.headers.get("User-Agent", "Router-DynDNS")[:80],
            auto_create=True,
        )
        if not ok:
            self._send_text(200, "nohost")
            return

        sync_to_cloudflare(sub, ipv4=rec.get("ipv4", ""), ipv6=rec.get("ipv6", ""))
        prefix = "good" if st == "UPDATED" else "nochg"
        self._send_text(200, f"{prefix} {v4 or v6}")

    def _handle_api_v1_update(self, user: Dict, payload: Dict) -> None:
        """Windows & macOS Masaüstü İstemcisi için Zengin JSON Güncelleme Uç Noktası."""
        domains = payload.get("domains", [])
        if isinstance(domains, str):
            domains = [d.strip() for d in domains.split(",") if d.strip()]
        if not domains:
            self._send_json(400, {"ok": False, "error": "En az bir alt alan adı (subdomain) belirtilmelidir."})
            return

        detected = detect_client_ip(self)
        raw_ip = str(payload.get("ipv4", "")).strip() or detected
        raw_ipv6 = str(payload.get("ipv6", "")).strip()
        client_info = str(payload.get("client_info", "")).strip() or self.headers.get("User-Agent", "DNSIP-Desktop")
        auto_create = bool(payload.get("auto_create", True))

        v4, v6 = validate_ip(raw_ip)
        if raw_ipv6:
            _, v6_explicit = validate_ip(raw_ipv6)
            if v6_explicit:
                v6 = v6_explicit

        settings = get_settings()
        base_domain = settings.get("base_domain", "").lower()
        results = []

        for sub in domains:
            sub_clean = str(sub).strip().lower()
            if base_domain and sub_clean.endswith("." + base_domain):
                sub_clean = sub_clean[: -(len(base_domain) + 1)]

            ok, st, rec = update_domain_record(
                user["id"],
                sub_clean,
                ipv4=v4,
                ipv6=v6,
                client_info=client_info[:100],
                auto_create=auto_create,
            )
            cf_ok, cf_msg = True, ""
            if ok:
                cf_ok, cf_msg = sync_to_cloudflare(
                    sub_clean, ipv4=rec.get("ipv4", ""), ipv6=rec.get("ipv6", "")
                )
            results.append(
                {
                    "subdomain": sub_clean,
                    "fqdn": f"{sub_clean}.{base_domain}",
                    "ok": ok,
                    "status": st,
                    "ipv4": rec.get("ipv4", ""),
                    "ipv6": rec.get("ipv6", ""),
                    "updated_at": rec.get("updated_at", ""),
                    "cloudflare_sync": cf_ok,
                    "cloudflare_message": cf_msg,
                }
            )

        self._send_json(
            200,
            {
                "ok": all(r["ok"] for r in results),
                "detected_ip": detected,
                "base_domain": base_domain,
                "results": results,
            },
        )

    # --- HTML ŞABLON MOTORU ---

    def _render_login(self, error_msg: str = "") -> None:
        err_html = (
            f'<div class="alert alert-err">{html.escape(error_msg)}</div>' if error_msg else ""
        )
        page = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DNSIP — Dinamik DNS Yönetim Paneli</title>
<style>
  :root {{
    --bg: #0f172a; --card: #1e293b; --border: #334155;
    --text: #f8fafc; --muted: #94a3b8; --accent: #38bdf8; --accent-hover: #0284c7;
    --danger: #ef4444;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
  body {{ background: var(--bg); color: var(--text); display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }}
  .login-box {{ background: var(--card); border: 1px solid var(--border); border-radius: 14px; width: 100%; max-width: 410px; padding: 34px; box-shadow: 0 20px 45px rgba(0,0,0,0.45); }}
  .brand {{ display: flex; align-items: center; gap: 12px; margin-bottom: 24px; }}
  .brand-icon {{ width: 42px; height: 42px; border-radius: 10px; background: linear-gradient(135deg, #38bdf8, #6366f1); display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 20px; color: #fff; }}
  h1 {{ font-size: 20px; font-weight: 700; }}
  p.sub {{ font-size: 13px; color: var(--muted); margin-top: 2px; }}
  label {{ display: block; font-size: 13px; color: var(--muted); margin-bottom: 6px; margin-top: 16px; }}
  input {{ width: 100%; padding: 11px 13px; border-radius: 8px; border: 1px solid var(--border); background: #0f172a; color: var(--text); font-size: 14px; outline: none; }}
  input:focus {{ border-color: var(--accent); }}
  button {{ margin-top: 24px; width: 100%; padding: 12px; border: none; border-radius: 8px; background: var(--accent); color: #0f172a; font-weight: 700; font-size: 14px; cursor: pointer; transition: 0.15s; }}
  button:hover {{ background: var(--accent-hover); color: #fff; }}
  .alert-err {{ background: rgba(239,68,68,0.15); border: 1px solid var(--danger); color: #fca5a5; padding: 10px 12px; border-radius: 8px; font-size: 13px; margin-bottom: 14px; }}
  .hint {{ margin-top: 18px; font-size: 12px; color: var(--muted); text-align: center; }}
</style>
</head>
<body>
  <div class="login-box">
    <div class="brand">
      <div class="brand-icon">D</div>
      <div>
        <h1>DNSIP Kontrol Paneli</h1>
        <p class="sub">Kişisel Dinamik DNS (DuckDNS) Sunucusu</p>
      </div>
    </div>
    {err_html}
    <form method="POST" action="/login">
      <label>Kullanıcı Adı</label>
      <input type="text" name="username" required autofocus placeholder="admin">
      <label>Şifre</label>
      <input type="password" name="password" required placeholder="••••••••">
      <button type="submit">Panele Giriş Yap</button>
    </form>
    <div class="hint">Varsayılan ilk giriş: <b>admin</b> / <b>admin123</b></div>
  </div>
</body>
</html>"""
        self._send_html(200, page)

    def _render_dashboard(self, user: Dict, msg: str = "", err: str = "") -> None:
        settings = get_settings()
        base_domain = settings.get("base_domain", "ornekalanadi.com")
        domains = list_domains(user["id"])
        logs = get_recent_logs(25)
        client_ip = detect_client_ip(self)
        host_header = self.headers.get("Host", f"{settings.get('server_public_ip', '127.0.0.1')}:8080")
        proto = "https" if self.headers.get("X-Forwarded-Proto") == "https" else "http"
        server_url = f"{proto}://{host_header}"

        alert_html = ""
        if msg:
            alert_html += f'<div class="alert alert-ok">{html.escape(msg)}</div>'
        if err:
            alert_html += f'<div class="alert alert-err">{html.escape(err)}</div>'

        domain_rows = ""
        for d in domains:
            sub = html.escape(d["subdomain"])
            fqdn = html.escape(f"{d['subdomain']}.{base_domain}")
            ipv4 = html.escape(d["ipv4"] or "")
            ipv6 = html.escape(d["ipv6"] or "")
            txt = html.escape(d["txt_record"] or "")
            updated = html.escape(d["updated_at"])
            agent = html.escape(d["last_client_info"] or "—")
            domain_rows += f"""
            <tr>
              <td>
                <div class="fqdn">{fqdn}</div>
                <div class="meta">Son Cihaz: {agent} • Güncelleme: {d['update_count']} kez</div>
              </td>
              <td>
                <form method="POST" action="/panel/domain/update" class="inline-form">
                  <input type="hidden" name="subdomain" value="{sub}">
                  <input type="text" name="ipv4" value="{ipv4}" placeholder="IPv4 (Örn: 85.100.1.1)" class="sm-input">
                  <input type="text" name="ipv6" value="{ipv6}" placeholder="IPv6 (Opsiyonel)" class="sm-input">
                  <input type="text" name="txt_record" value="{txt}" placeholder="TXT Kaydı" class="sm-input">
                  <button type="submit" class="btn btn-sm">Kaydet</button>
                </form>
              </td>
              <td class="meta">{updated}</td>
              <td>
                <form method="POST" action="/panel/domain/delete" onsubmit="return confirm('{fqdn} silinsin mi?');">
                  <input type="hidden" name="subdomain" value="{sub}">
                  <button type="submit" class="btn btn-sm btn-danger">Sil</button>
                </form>
              </td>
            </tr>
            """
        if not domain_rows:
            domain_rows = '<tr><td colspan="4" style="text-align:center;color:#94a3b8;padding:24px;">Henüz alt alan adı eklenmemiş. Yukarıdan ilk alt alan adınızı (örn: <b>ev</b> veya <b>macbook</b>) oluşturun.</td></tr>'

        log_rows = ""
        for lg in logs:
            log_rows += f"""
            <tr>
              <td><b>{html.escape(lg['subdomain'])}.{html.escape(base_domain)}</b></td>
              <td><code>{html.escape(lg['old_ip'] or '—')}</code> &rarr; <code>{html.escape(lg['new_ip'] or '—')}</code></td>
              <td>{html.escape(lg['client_info'] or '—')}</td>
              <td><span class="badge">{html.escape(lg['status'])}</span></td>
              <td class="meta">{html.escape(lg['created_at'])}</td>
            </tr>
            """
        if not log_rows:
            log_rows = '<tr><td colspan="5" style="text-align:center;color:#94a3b8;padding:16px;">Henüz IP değişim kaydı yok.</td></tr>'

        dns_badge = (
            f'<span class="status-pill ok">● DNS Port {html.escape(settings.get("dns_port", "53"))} Aktif</span>'
            if DNS_SERVER_STATUS[0]
            else f'<span class="status-pill warn" title="{html.escape(DNS_SERVER_STATUS[1])}">● DNS Port {html.escape(settings.get("dns_port", "53"))} Uyarı ({html.escape(DNS_SERVER_STATUS[1][:45])}...)</span>'
        )

        cf_checked = "checked" if settings.get("cf_enabled") == "1" else ""
        example_sub = domains[0]["subdomain"] if domains else "ev"
        sample_update_url = f"{server_url}/update?domains={example_sub}&token={user['api_token']}&ip="

        page = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DNSIP — Kontrol Paneli ({html.escape(base_domain)})</title>
<style>
  :root {{
    --bg: #0b1120; --card: #1e293b; --border: #334155;
    --text: #f8fafc; --muted: #94a3b8; --accent: #38bdf8; --accent-hover: #0284c7;
    --ok: #22c55e; --warn: #f59e0b; --danger: #ef4444;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
  body {{ background: var(--bg); color: var(--text); padding-bottom: 60px; }}
  header {{ background: #0f172a; border-bottom: 1px solid var(--border); padding: 16px 28px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; }}
  .brand {{ display: flex; align-items: center; gap: 12px; }}
  .brand-icon {{ width: 36px; height: 36px; border-radius: 9px; background: linear-gradient(135deg, #38bdf8, #6366f1); display: flex; align-items: center; justify-content: center; font-weight: 800; color: #fff; }}
  .container {{ max-width: 1220px; margin: 26px auto; padding: 0 20px; display: grid; gap: 22px; }}
  .grid-2 {{ display: grid; grid-template-columns: 1.2fr 1fr; gap: 22px; }}
  @media (max-width: 900px) {{ .grid-2 {{ grid-template-columns: 1fr; }} }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 22px; }}
  .card h2 {{ font-size: 16px; margin-bottom: 14px; display: flex; align-items: center; justify-content: space-between; }}
  .status-pill {{ font-size: 12px; padding: 5px 10px; border-radius: 999px; font-weight: 600; }}
  .status-pill.ok {{ background: rgba(34,197,94,0.15); color: #4ade80; border: 1px solid rgba(34,197,94,0.3); }}
  .status-pill.warn {{ background: rgba(245,158,11,0.15); color: #fbbf24; border: 1px solid rgba(245,158,11,0.3); }}
  .token-box {{ display: flex; align-items: center; gap: 10px; background: #0f172a; border: 1px solid var(--border); padding: 10px 14px; border-radius: 8px; font-family: monospace; font-size: 14px; color: #38bdf8; overflow-x: auto; }}
  input[type="text"], input[type="password"], input[type="number"] {{
    padding: 9px 12px; border-radius: 7px; border: 1px solid var(--border); background: #0f172a; color: var(--text); font-size: 13px;
  }}
  .btn {{ padding: 9px 15px; border-radius: 7px; border: none; background: var(--accent); color: #0f172a; font-weight: 700; font-size: 13px; cursor: pointer; text-decoration: none; display: inline-block; }}
  .btn:hover {{ background: var(--accent-hover); color: #fff; }}
  .btn-sm {{ padding: 6px 11px; font-size: 12px; }}
  .btn-outline {{ background: transparent; border: 1px solid var(--border); color: var(--text); }}
  .btn-danger {{ background: rgba(239,68,68,0.2); color: #fca5a5; border: 1px solid rgba(239,68,68,0.4); }}
  .btn-danger:hover {{ background: var(--danger); color: #fff; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
  th, td {{ text-align: left; padding: 12px 10px; border-bottom: 1px solid var(--border); font-size: 13px; }}
  th {{ color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; }}
  .fqdn {{ font-weight: 700; font-size: 15px; color: #38bdf8; }}
  .meta {{ font-size: 12px; color: var(--muted); margin-top: 3px; }}
  .inline-form {{ display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }}
  .sm-input {{ width: 145px; }}
  .alert {{ padding: 12px 16px; border-radius: 9px; font-size: 13px; font-weight: 500; }}
  .alert-ok {{ background: rgba(34,197,94,0.15); border: 1px solid var(--ok); color: #86efac; }}
  .alert-err {{ background: rgba(239,68,68,0.15); border: 1px solid var(--danger); color: #fca5a5; }}
  .form-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
  .form-group label {{ display: block; font-size: 12px; color: var(--muted); margin-bottom: 4px; }}
  .form-group input {{ width: 100%; }}
  code {{ background: #0f172a; padding: 3px 6px; border-radius: 5px; font-family: monospace; font-size: 12px; color: #e2e8f0; }}
  .badge {{ background: rgba(56,189,248,0.15); color: #38bdf8; padding: 2px 8px; border-radius: 5px; font-size: 11px; font-weight: 700; }}
</style>
</head>
<body>
<header>
  <div class="brand">
    <div class="brand-icon">D</div>
    <div>
      <div style="font-weight:700;font-size:16px;">DNSIP Dinamik DNS Sunucusu</div>
      <div style="font-size:12px;color:var(--muted);">Ana Alan Adı: <b>*.{html.escape(base_domain)}</b> • Algılanan IP'niz: <b>{html.escape(client_ip)}</b></div>
    </div>
  </div>
  <div style="display:flex;align-items:center;gap:12px;">
    {dns_badge}
    <a href="/logout" class="btn btn-sm btn-outline">Çıkış Yap ({html.escape(user['username'])})</a>
  </div>
</header>

<div class="container">
  {alert_html}

  <div class="grid-2">
    <!-- TOKEN & HIZLI BAĞLANTI KARTI -->
    <div class="card">
      <h2>
        <span>🔑 API Token Anahtarınız</span>
        <form method="POST" action="/panel/token/regenerate" onsubmit="return confirm('Token yenilendiğinde bağlı masaüstü istemcilerinizde yeni tokenı girmeniz gerekir. Onaylıyor musunuz?');">
          <button type="submit" class="btn btn-sm btn-outline">🔄 Token Yenile</button>
        </form>
      </h2>
      <div class="token-box" id="apiToken">{html.escape(user['api_token'])}</div>
      <p class="meta" style="margin-top:10px;">
        Windows ve macOS masaüstü uygulamasında <b>Sunucu Adresi</b> olarak <code>{html.escape(server_url)}</code> ve yukarıdaki <b>API Token</b> değerini girin.
      </p>
      <div style="margin-top:14px;">
        <div style="font-size:12px;color:var(--muted);margin-bottom:4px;">DuckDNS Uyumlu Doğrudan Güncelleme URL'si (Modem / Cron / cURL):</div>
        <div class="token-box" style="font-size:12px;color:#cbd5e1;">{html.escape(sample_update_url)}</div>
      </div>
    </div>

    <!-- YENİ ALT ALAN ADI EKLEME -->
    <div class="card">
      <h2>➕ Yeni Alt Alan Adı (Subdomain) Ekle</h2>
      <form method="POST" action="/panel/domain/create">
        <div style="display:flex;gap:8px;align-items:center;margin-bottom:12px;">
          <input type="text" name="subdomain" required placeholder="ev, ofis, macbook" style="flex:1;">
          <span style="color:var(--muted);font-weight:700;">.{html.escape(base_domain)}</span>
        </div>
        <div style="display:flex;gap:8px;align-items:center;">
          <input type="text" name="ipv4" value="{html.escape(client_ip)}" placeholder="Başlangıç IPv4 Adresi" style="flex:1;">
          <button type="submit" class="btn">Alt Alan Adı Oluştur</button>
        </div>
        <p class="meta" style="margin-top:10px;">
          Not: Masaüstü uygulamasından (Windows / macOS) bağlandığınızda yazdığınız alt alan adı yoksa otomatik olarak da oluşturulur.
        </p>
      </form>
    </div>
  </div>

  <!-- ALT ALAN ADLARI TABLOSU -->
  <div class="card">
    <h2>🌐 Kayıtlı Alt Alan Adlarınız ({len(domains)})</h2>
    <div style="overflow-x:auto;">
      <table>
        <thead>
          <tr>
            <th>Tam Alan Adı (FQDN)</th>
            <th>IPv4 / IPv6 / TXT Kayıtları</th>
            <th>Son Güncelleme</th>
            <th>İşlem</th>
          </tr>
        </thead>
        <tbody>
          {domain_rows}
        </tbody>
      </table>
    </div>
  </div>

  <div class="grid-2">
    <!-- SUNUCU & DNS AYARLARI -->
    <div class="card">
      <h2>⚙️ Alan Adı & DNS Sunucu Ayarları</h2>
      <form method="POST" action="/panel/settings">
        <div class="form-grid">
          <div class="form-group">
            <label>Ana Alan Adı (Base Domain)</label>
            <input type="text" name="base_domain" value="{html.escape(settings.get('base_domain', ''))}" required>
          </div>
          <div class="form-group">
            <label>VPS Sunucu Public IP Adresi</label>
            <input type="text" name="server_public_ip" value="{html.escape(settings.get('server_public_ip', ''))}" required>
          </div>
          <div class="form-group">
            <label>Birincil NS (Glue Record NS1)</label>
            <input type="text" name="ns1_host" value="{html.escape(settings.get('ns1_host', ''))}">
          </div>
          <div class="form-group">
            <label>İkincil NS (Glue Record NS2)</label>
            <input type="text" name="ns2_host" value="{html.escape(settings.get('ns2_host', ''))}">
          </div>
          <div class="form-group">
            <label>Varsayılan DNS TTL (Saniye)</label>
            <input type="number" name="default_ttl" value="{html.escape(settings.get('default_ttl', '60'))}">
          </div>
        </div>

        <hr style="border:none;border-top:1px solid var(--border);margin:16px 0;">
        <div style="margin-bottom:10px;">
          <label style="font-size:13px;cursor:pointer;display:flex;align-items:center;gap:8px;">
            <input type="checkbox" name="cf_enabled" value="1" {cf_checked}>
            <b>Opsiyonel: Cloudflare DNS Senkronizasyonu</b> (Alan adınız Cloudflare'da ise güncellemeleri Cloudflare'a da yansıt)
          </label>
        </div>
        <div class="form-grid">
          <div class="form-group">
            <label>Cloudflare API Token (Zone.DNS Edit)</label>
            <input type="password" name="cf_api_token" value="{html.escape(settings.get('cf_api_token', ''))}" placeholder="Opsiyonel">
          </div>
          <div class="form-group">
            <label>Cloudflare Zone ID</label>
            <input type="text" name="cf_zone_id" value="{html.escape(settings.get('cf_zone_id', ''))}" placeholder="Opsiyonel">
          </div>
        </div>
        <button type="submit" class="btn" style="margin-top:14px;">Ayarları Kaydet</button>
      </form>
    </div>

    <!-- YÖNETİCİ HESABI & KURULUM REHBERİ -->
    <div class="card">
      <h2>🛡️ Yönetici Hesabı & Alan Adı Bağlama Özeti</h2>
      <form method="POST" action="/panel/account" style="margin-bottom:18px;">
        <div class="form-grid">
          <div class="form-group">
            <label>Yönetici Kullanıcı Adı</label>
            <input type="text" name="username" value="{html.escape(user['username'])}" required>
          </div>
          <div class="form-group">
            <label>Yeni Şifre (Değiştirmek için doldurun)</label>
            <input type="password" name="new_password" placeholder="••••••••">
          </div>
        </div>
        <button type="submit" class="btn btn-sm" style="margin-top:10px;">Hesabı Güncelle</button>
      </form>

      <div style="background:#0f172a;border:1px solid var(--border);border-radius:8px;padding:12px;font-size:12px;line-height:1.6;color:#cbd5e1;">
        <b style="color:#38bdf8;">Nasıl Alan Adınıza Bağlarsınız? (2 Yöntemden Birini Seçin):</b><br>
        <b>Yöntem A (Tam Bağımsız Otoriter DNS - Port 53):</b> Domain firmanızın panelinden <code>ns1.{html.escape(base_domain)}</code> &rarr; <code>{html.escape(settings.get('server_public_ip', 'VPS_IP'))}</code> olarak Glue/Child Nameserver tanımlayın ve alan adınızın NS kayıtlarını bu sunucuya yönlendirin.<br>
        <b>Yöntem B (Alt Alan Adı NS Delegasyonu):</b> Mevcut DNS panelinizde sadece <code>ddns.{html.escape(base_domain)}</code> için <code>NS</code> kaydını VPS sunucunuza yönlendirin.<br>
        <b>Yöntem C (Cloudflare Köprüsü):</b> Port 53 ile uğraşmak istemiyorsanız sol taraftan Cloudflare API Token ve Zone ID girin; sunucu tüm A/AAAA kayıtlarını anında Cloudflare'a işlesin.
      </div>
    </div>
  </div>

  <!-- SON IP DEĞİŞİM LOGLARI -->
  <div class="card">
    <h2>📜 Son IP Güncelleme Geçmişi</h2>
    <div style="overflow-x:auto;">
      <table>
        <thead>
          <tr>
            <th>Alan Adı</th>
            <th>IP Değişimi</th>
            <th>İstemci / Cihaz (Windows / macOS)</th>
            <th>Durum</th>
            <th>Zaman</th>
          </tr>
        </thead>
        <tbody>
          {log_rows}
        </tbody>
      </table>
    </div>
  </div>
</div>
</body>
</html>"""
        self._send_html(200, page)


def run_server() -> None:
    global DNS_SERVER_INSTANCE, DNS_SERVER_STATUS
    init_db()
    settings = get_settings()

    dns_port = int(os.environ.get("DNSIP_DNS_PORT", settings.get("dns_port", "53")))
    http_port = int(os.environ.get("DNSIP_HTTP_PORT", "8080"))
    bind_host = os.environ.get("DNSIP_BIND_HOST", "0.0.0.0")

    # 1. Otoriter DNS Sunucusunu başlat (UDP/TCP Port 53 veya yapılandırılan port)
    DNS_SERVER_INSTANCE = PurePythonDNSServer(host=bind_host, port=dns_port)
    ok, msg = DNS_SERVER_INSTANCE.start()
    DNS_SERVER_STATUS = (ok, msg)
    if not ok and dns_port == 53:
        # Eğer root değilse veya 53 portu doluysa, yedek olarak 5353 portunda da dene
        fallback_port = 5354
        fallback_dns = PurePythonDNSServer(host=bind_host, port=fallback_port)
        f_ok, f_msg = fallback_dns.start()
        if f_ok:
            DNS_SERVER_INSTANCE = fallback_dns
            DNS_SERVER_STATUS = (
                False,
                f"Port 53 açılamadı ({msg}). Test için Port {fallback_port} üzerinde çalışıyor.",
            )

    # 2. HTTP Web Paneli ve DuckDNS API Sunucusunu başlat
    httpd = ThreadingHTTPServer((bind_host, http_port), DNSIPHTTPHandler)
    logger.info(f"DNSIP Web Paneli ve API Sunucusu http://{bind_host}:{http_port} üzerinde çalışıyor.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Sunucu kapatılıyor...")
        if DNS_SERVER_INSTANCE:
            DNS_SERVER_INSTANCE.stop()
        httpd.server_close()


if __name__ == "__main__":
    run_server()
