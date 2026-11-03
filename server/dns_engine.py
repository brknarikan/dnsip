import ipaddress
import json
import logging
import socket
import struct
import threading
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

from database import get_domain_by_sub, get_settings

logger = logging.getLogger("dnsip.dns_engine")


def encode_dns_name(domain: str) -> bytes:
    """Alan adını RFC 1035 DNS etiket formatına dönüştürür."""
    domain = domain.strip(".")
    if not domain:
        return b"\x00"
    parts = domain.encode("ascii", errors="ignore").split(b".")
    return b"".join(struct.pack("!B", len(p)) + p for p in parts) + b"\x00"


def decode_dns_name(packet: bytes, offset: int) -> Tuple[str, int]:
    """DNS paketinden sıkıştırılmış veya normal alan adını okur."""
    labels = []
    jumped = False
    original_offset = offset
    max_jumps = 15
    jumps = 0

    while True:
        if offset >= len(packet):
            break
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        # Sıkıştırma işaretçisi (Compression pointer: üst 2 bit 11)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(packet):
                break
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if not jumped:
                original_offset = offset + 2
                jumped = True
            offset = pointer
            jumps += 1
            if jumps > max_jumps:
                break
            continue
        else:
            offset += 1
            labels.append(packet[offset : offset + length].decode("ascii", errors="ignore"))
            offset += length

    final_offset = original_offset if jumped else offset
    return ".".join(labels), final_offset


class PurePythonDNSServer:
    """
    Harici kütüphane gerektirmeyen, RFC 1035 uyumlu, çok iş parçacıklı (UDP + TCP)
    Otoriter (Authoritative) Dinamik DNS Sunucusu.
    Desteklenen kayıt tipleri: A (1), NS (2), SOA (6), TXT (16), AAAA (28), ANY (255).
    """

    TYPE_A = 1
    TYPE_NS = 2
    TYPE_SOA = 6
    TYPE_TXT = 16
    TYPE_AAAA = 28
    TYPE_ANY = 255
    CLASS_IN = 1

    def __init__(self, host: str = "0.0.0.0", port: int = 53):
        self.host = host
        self.port = port
        self.running = False
        self.udp_sock: Optional[socket.socket] = None
        self.tcp_sock: Optional[socket.socket] = None
        self._threads: List[threading.Thread] = []

    def start(self) -> Tuple[bool, str]:
        if self.running:
            return True, f"DNS sunucusu zaten port {self.port} üzerinde çalışıyor."
        try:
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_sock.bind((self.host, self.port))

            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_sock.bind((self.host, self.port))
            self.tcp_sock.listen(32)

            self.running = True

            t_udp = threading.Thread(target=self._udp_loop, name="DNS-UDP-Loop", daemon=True)
            t_tcp = threading.Thread(target=self._tcp_loop, name="DNS-TCP-Loop", daemon=True)
            t_udp.start()
            t_tcp.start()
            self._threads = [t_udp, t_tcp]

            logger.info(f"Otoriter DNS Sunucusu {self.host}:{self.port} (UDP/TCP) üzerinde başlatıldı.")
            return True, f"DNS Sunucusu {self.host}:{self.port} (UDP/TCP) üzerinde aktif."
        except PermissionError:
            msg = (
                f"Port {self.port} için yetki hatası (root/Administrator gerekli) veya "
                f"port başka bir servis (örn. systemd-resolved) tarafından kullanılıyor."
            )
            logger.warning(msg)
            return False, msg
        except OSError as exc:
            msg = f"DNS Sunucusu port {self.port} üzerinde başlatılamadı: {exc}"
            logger.warning(msg)
            return False, msg

    def stop(self) -> None:
        self.running = False
        for sock in (self.udp_sock, self.tcp_sock):
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _udp_loop(self) -> None:
        while self.running and self.udp_sock:
            try:
                data, addr = self.udp_sock.recvfrom(1024)
                response = self.handle_dns_query(data)
                if response:
                    self.udp_sock.sendto(response, addr)
            except Exception as exc:
                if self.running:
                    logger.debug(f"UDP DNS hatası: {exc}")

    def _tcp_loop(self) -> None:
        while self.running and self.tcp_sock:
            try:
                conn, _ = self.tcp_sock.accept()
                threading.Thread(target=self._handle_tcp_client, args=(conn,), daemon=True).start()
            except Exception as exc:
                if self.running:
                    logger.debug(f"TCP DNS hatası: {exc}")

    def _handle_tcp_client(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(5.0)
            try:
                length_bytes = conn.recv(2)
                if len(length_bytes) < 2:
                    return
                msg_len = struct.unpack("!H", length_bytes)[0]
                data = conn.recv(msg_len)
                response = self.handle_dns_query(data)
                if response:
                    conn.sendall(struct.pack("!H", len(response)) + response)
            except Exception:
                pass

    def handle_dns_query(self, data: bytes) -> Optional[bytes]:
        if len(data) < 12:
            return None

        tid, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", data[:12])
        if qdcount < 1:
            return None

        qname, offset = decode_dns_name(data, 12)
        if offset + 4 > len(data):
            return None

        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        question_section = data[12 : offset + 4]

        settings = get_settings()
        base_domain = settings.get("base_domain", "ornekalanadi.com").lower().strip(".")
        ns1_host = settings.get("ns1_host", f"ns1.{base_domain}").lower().strip(".")
        ns2_host = settings.get("ns2_host", f"ns2.{base_domain}").lower().strip(".")
        server_ip = settings.get("server_public_ip", "127.0.0.1").strip()
        default_ttl = int(settings.get("default_ttl", "60") or 60)

        qname_clean = qname.lower().strip(".")
        answers: List[bytes] = []
        rcode = 0  # 0 = NOERROR, 3 = NXDOMAIN

        # 1. Sorgu bu sunucunun yönettiği base_domain altında mı?
        if qname_clean == base_domain or qname_clean.endswith("." + base_domain):
            sub_part = ""
            if qname_clean != base_domain:
                sub_part = qname_clean[: -(len(base_domain) + 1)]

            # Let's Encrypt _acme-challenge.<subdomain> desteği
            if sub_part.startswith("_acme-challenge."):
                sub_part = sub_part[len("_acme-challenge.") :]
            elif sub_part == "_acme-challenge":
                sub_part = ""

            # Ana domain veya NS sunucusu sorgusu (örn. ns1.alanadim.com veya alanadim.com)
            if qname_clean in (base_domain, ns1_host, ns2_host):
                if qtype in (self.TYPE_NS, self.TYPE_ANY) and qname_clean == base_domain:
                    answers.append(self._build_rr(qname, self.TYPE_NS, 300, encode_dns_name(ns1_host)))
                    answers.append(self._build_rr(qname, self.TYPE_NS, 300, encode_dns_name(ns2_host)))
                if qtype in (self.TYPE_SOA, self.TYPE_ANY) and qname_clean == base_domain:
                    soa_rdata = self._build_soa_rdata(ns1_host, f"hostmaster.{base_domain}")
                    answers.append(self._build_rr(qname, self.TYPE_SOA, 300, soa_rdata))
                if qtype in (self.TYPE_A, self.TYPE_ANY):
                    try:
                        ip_bytes = ipaddress.IPv4Address(server_ip).packed
                        answers.append(self._build_rr(qname, self.TYPE_A, 300, ip_bytes))
                    except Exception:
                        pass
            else:
                # Alt alan adı sorgusu (örn: ev.alanadim.com veya *.ev.alanadim.com)
                # Çok seviyeli alt alan adı gelirse (örn. app.ev.alanadim.com) son etiketi ('ev') baz al
                target_sub = sub_part.split(".")[-1]
                record = get_domain_by_sub(target_sub)
                if not record:
                    rcode = 3  # NXDOMAIN
                else:
                    ttl = int(record.get("ttl") or default_ttl)
                    ipv4_str = (record.get("ipv4") or "").strip()
                    ipv6_str = (record.get("ipv6") or "").strip()
                    txt_str = (record.get("txt_record") or "").strip()

                    if qtype in (self.TYPE_A, self.TYPE_ANY) and ipv4_str:
                        try:
                            ip4_bytes = ipaddress.IPv4Address(ipv4_str).packed
                            answers.append(self._build_rr(qname, self.TYPE_A, ttl, ip4_bytes))
                        except Exception:
                            pass

                    if qtype in (self.TYPE_AAAA, self.TYPE_ANY) and ipv6_str:
                        try:
                            ip6_bytes = ipaddress.IPv6Address(ipv6_str).packed
                            answers.append(self._build_rr(qname, self.TYPE_AAAA, ttl, ip6_bytes))
                        except Exception:
                            pass

                    if qtype in (self.TYPE_TXT, self.TYPE_ANY) and txt_str:
                        txt_bytes = txt_str.encode("utf-8")[:255]
                        rdata = struct.pack("!B", len(txt_bytes)) + txt_bytes
                        answers.append(self._build_rr(qname, self.TYPE_TXT, ttl, rdata))
        else:
            # Yabancı alan adı sorgularına REFUSED (5) dön (Open Resolver olarak kötüye kullanımı engeller)
            rcode = 5

        # DNS Yanıt Başlığı (QR=1, AA=1 [Authoritative Answer], RD=istekten kopyala, RA=0)
        rd_bit = flags & 0x0100
        resp_flags = 0x8400 | rd_bit | (rcode & 0x000F)
        header = struct.pack("!HHHHHH", tid, resp_flags, 1, len(answers), 0, 0)
        return header + question_section + b"".join(answers)

    def _build_rr(self, qname: str, rtype: int, ttl: int, rdata: bytes) -> bytes:
        name_bytes = encode_dns_name(qname)
        return name_bytes + struct.pack("!HHIH", rtype, self.CLASS_IN, ttl, len(rdata)) + rdata

    def _build_soa_rdata(self, mname: str, rname: str) -> bytes:
        serial = int(time.strftime("%Y%m%d01"))
        return (
            encode_dns_name(mname)
            + encode_dns_name(rname)
            + struct.pack("!IIIII", serial, 3600, 600, 86400, 60)
        )


def sync_to_cloudflare(subdomain: str, ipv4: str = "", ipv6: str = "", txt: str = "") -> Tuple[bool, str]:
    """
    Eğer sunucu ayarlarında Cloudflare entegrasyonu (cf_enabled = 1) açıksa,
    alt alan adı güncellemesini Cloudflare DNS üzerindeki ilgili A / AAAA / TXT kaydına da yansıtır.
    """
    settings = get_settings()
    if settings.get("cf_enabled") != "1":
        return True, "Cloudflare senkronizasyonu devre dışı."

    api_token = settings.get("cf_api_token", "").strip()
    zone_id = settings.get("cf_zone_id", "").strip()
    base_domain = settings.get("base_domain", "").strip(".")

    if not api_token or not zone_id or not base_domain:
        return False, "Cloudflare API Token, Zone ID veya Base Domain eksik."

    fqdn = f"{subdomain}.{base_domain}"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }

    try:
        if ipv4:
            _upsert_cf_record(zone_id, headers, "A", fqdn, ipv4)
        if ipv6:
            _upsert_cf_record(zone_id, headers, "AAAA", fqdn, ipv6)
        if txt:
            _upsert_cf_record(zone_id, headers, "TXT", fqdn, txt)
        return True, f"Cloudflare DNS güncellendi ({fqdn})"
    except Exception as exc:
        logger.warning(f"Cloudflare senkronizasyon hatası: {exc}")
        return False, f"Cloudflare hatası: {exc}"


def _upsert_cf_record(zone_id: str, headers: Dict[str, str], rtype: str, fqdn: str, content: str) -> None:
    list_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type={rtype}&name={fqdn}"
    req = urllib.request.Request(list_url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    payload = json.dumps(
        {
            "type": rtype,
            "name": fqdn,
            "content": content,
            "ttl": 60,
            "proxied": False,
        }
    ).encode("utf-8")

    records = data.get("result", [])
    if records:
        rec_id = records[0]["id"]
        update_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rec_id}"
        ureq = urllib.request.Request(update_url, data=payload, headers=headers, method="PUT")
        urllib.request.urlopen(ureq, timeout=10).read()
    else:
        create_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        creq = urllib.request.Request(create_url, data=payload, headers=headers, method="POST")
        urllib.request.urlopen(creq, timeout=10).read()
