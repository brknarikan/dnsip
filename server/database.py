import os
import secrets
import sqlite3
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

DB_PATH = os.environ.get("DNSIP_DB_PATH", os.path.join(os.path.dirname(__file__), "data", "dnsip.db"))


def get_connection() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def hash_password(password: str, salt: Optional[str] = None) -> str:
    if not salt:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return f"{salt}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, _ = stored_hash.split("$", 1)
        return secrets.compare_digest(hash_password(password, salt), stored_hash)
    except Exception:
        return False


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def init_db() -> None:
    conn = get_connection()
    with conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                api_token TEXT UNIQUE NOT NULL,
                is_admin INTEGER DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                subdomain TEXT UNIQUE NOT NULL,
                ipv4 TEXT DEFAULT '',
                ipv6 TEXT DEFAULT '',
                txt_record TEXT DEFAULT '',
                ttl INTEGER DEFAULT 60,
                last_client_info TEXT DEFAULT '',
                update_count INTEGER DEFAULT 0,
                updated_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS ip_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subdomain TEXT NOT NULL,
                old_ip TEXT DEFAULT '',
                new_ip TEXT DEFAULT '',
                client_info TEXT DEFAULT '',
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )

        # Varsayılan ayarları ekle
        default_settings = {
            "base_domain": os.environ.get("DNSIP_BASE_DOMAIN", "ornekalanadi.com"),
            "ns1_host": os.environ.get("DNSIP_NS1", "ns1.ornekalanadi.com"),
            "ns2_host": os.environ.get("DNSIP_NS2", "ns2.ornekalanadi.com"),
            "server_public_ip": os.environ.get("DNSIP_SERVER_IP", "127.0.0.1"),
            "default_ttl": "60",
            "dns_port": os.environ.get("DNSIP_DNS_PORT", "53"),
            "cf_enabled": "0",
            "cf_api_token": "",
            "cf_zone_id": "",
        }
        for k, v in default_settings.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
                (k, v),
            )

        # Varsayılan admin kullanıcısını oluştur (Eğer hiç kullanıcı yoksa)
        cur = conn.execute("SELECT COUNT(*) as cnt FROM users")
        if cur.fetchone()["cnt"] == 0:
            default_user = os.environ.get("DNSIP_ADMIN_USER", "admin")
            default_pass = os.environ.get("DNSIP_ADMIN_PASS", "admin123")
            token = secrets.token_urlsafe(24)
            conn.execute(
                """
                INSERT INTO users (username, password_hash, api_token, is_admin, created_at)
                VALUES (?, ?, ?, 1, ?)
                """,
                (default_user, hash_password(default_pass), token, now_iso()),
            )
    conn.close()


def get_settings() -> Dict[str, str]:
    conn = get_connection()
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    conn.close()
    return {row["key"]: row["value"] for row in rows}


def update_settings(new_settings: Dict[str, str]) -> None:
    conn = get_connection()
    with conn:
        for k, v in new_settings.items():
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (k, str(v).strip()),
            )
    conn.close()


def get_user_by_username(username: str) -> Optional[Dict]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_token(token: str) -> Optional[Dict]:
    if not token:
        return None
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE api_token = ?", (token.strip(),)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[Dict]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def regenerate_user_token(user_id: int) -> str:
    new_token = secrets.token_urlsafe(24)
    conn = get_connection()
    with conn:
        conn.execute("UPDATE users SET api_token = ? WHERE id = ?", (new_token, user_id))
    conn.close()
    return new_token


def update_user_credentials(user_id: int, username: str, new_password: Optional[str] = None) -> None:
    conn = get_connection()
    with conn:
        if new_password:
            conn.execute(
                "UPDATE users SET username = ?, password_hash = ? WHERE id = ?",
                (username.strip(), hash_password(new_password), user_id),
            )
        else:
            conn.execute(
                "UPDATE users SET username = ? WHERE id = ?",
                (username.strip(), user_id),
            )
    conn.close()


def list_domains(user_id: Optional[int] = None) -> List[Dict]:
    conn = get_connection()
    if user_id is not None:
        rows = conn.execute(
            "SELECT * FROM domains WHERE user_id = ? ORDER BY subdomain ASC", (user_id,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM domains ORDER BY subdomain ASC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_domain_by_sub(subdomain: str) -> Optional[Dict]:
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM domains WHERE subdomain = ?", (subdomain.lower().strip(),)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def create_domain(user_id: int, subdomain: str, ipv4: str = "", ipv6: str = "", ttl: int = 60) -> Tuple[bool, str]:
    sub = subdomain.lower().strip()
    if not sub or not all(c.isalnum() or c == "-" for c in sub) or sub.startswith("-") or sub.endswith("-"):
        return False, "Geçersiz alt alan adı formatı. Sadece harf, rakam ve tire (-) kullanılabilir."

    conn = get_connection()
    existing = conn.execute("SELECT id FROM domains WHERE subdomain = ?", (sub,)).fetchone()
    if existing:
        conn.close()
        return False, f"'{sub}' alt alan adı zaten mevcut."

    now = now_iso()
    with conn:
        conn.execute(
            """
            INSERT INTO domains (user_id, subdomain, ipv4, ipv6, ttl, updated_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, sub, ipv4.strip(), ipv6.strip(), int(ttl), now, now),
        )
    conn.close()
    return True, f"'{sub}' başarıyla oluşturuldu."


def delete_domain(user_id: int, subdomain: str, is_admin: bool = False) -> bool:
    sub = subdomain.lower().strip()
    conn = get_connection()
    with conn:
        if is_admin:
            cur = conn.execute("DELETE FROM domains WHERE subdomain = ?", (sub,))
        else:
            cur = conn.execute("DELETE FROM domains WHERE subdomain = ? AND user_id = ?", (sub, user_id))
    deleted = cur.rowcount > 0
    conn.close()
    return deleted


def update_domain_record(
    user_id: int,
    subdomain: str,
    ipv4: Optional[str] = None,
    ipv6: Optional[str] = None,
    txt_record: Optional[str] = None,
    clear_txt: bool = False,
    client_info: str = "",
    auto_create: bool = False,
) -> Tuple[bool, str, Dict]:
    """
    Alt alan adının IP veya TXT kaydını günceller.
    Dönüş: (başarılı_mı, durum_mesajı ['UPDATED' | 'NOCHANGE' | 'ERROR'], güncel_kayıt_sözlüğü)
    """
    sub = subdomain.lower().strip()
    conn = get_connection()
    row = conn.execute("SELECT * FROM domains WHERE subdomain = ?", (sub,)).fetchone()

    if not row:
        if auto_create:
            now = now_iso()
            with conn:
                conn.execute(
                    """
                    INSERT INTO domains (user_id, subdomain, ipv4, ipv6, txt_record, ttl, last_client_info, update_count, updated_at, created_at)
                    VALUES (?, ?, ?, ?, ?, 60, ?, 1, ?, ?)
                    """,
                    (
                        user_id,
                        sub,
                        ipv4 or "",
                        ipv6 or "",
                        "" if clear_txt else (txt_record or ""),
                        client_info,
                        now,
                        now,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO ip_logs (subdomain, old_ip, new_ip, client_info, status, created_at)
                    VALUES (?, ?, ?, ?, 'CREATED', ?)
                    """,
                    (sub, "", ipv4 or ipv6 or "", client_info, now),
                )
            new_row = conn.execute("SELECT * FROM domains WHERE subdomain = ?", (sub,)).fetchone()
            conn.close()
            return True, "UPDATED", dict(new_row)
        else:
            conn.close()
            return False, "NOT_FOUND", {}

    record = dict(row)
    if record["user_id"] != user_id:
        conn.close()
        return False, "FORBIDDEN", {}

    old_ipv4 = record["ipv4"] or ""
    old_ipv6 = record["ipv6"] or ""
    old_txt = record["txt_record"] or ""

    new_ipv4 = ipv4.strip() if ipv4 is not None else old_ipv4
    new_ipv6 = ipv6.strip() if ipv6 is not None else old_ipv6
    if clear_txt:
        new_txt = ""
    elif txt_record is not None:
        new_txt = txt_record.strip()
    else:
        new_txt = old_txt

    changed = (new_ipv4 != old_ipv4) or (new_ipv6 != old_ipv6) or (new_txt != old_txt)
    now = now_iso()

    with conn:
        conn.execute(
            """
            UPDATE domains
            SET ipv4 = ?, ipv6 = ?, txt_record = ?, last_client_info = ?,
                update_count = update_count + 1, updated_at = ?
            WHERE id = ?
            """,
            (new_ipv4, new_ipv6, new_txt, client_info or record["last_client_info"], now, record["id"]),
        )
        if changed:
            conn.execute(
                """
                INSERT INTO ip_logs (subdomain, old_ip, new_ip, client_info, status, created_at)
                VALUES (?, ?, ?, ?, 'UPDATED', ?)
                """,
                (sub, old_ipv4 or old_ipv6, new_ipv4 or new_ipv6, client_info, now),
            )
            # Log tablosunu son 500 kayıtla sınırla
            conn.execute(
                """
                DELETE FROM ip_logs WHERE id NOT IN (
                    SELECT id FROM ip_logs ORDER BY id DESC LIMIT 500
                )
                """
            )

    updated_row = conn.execute("SELECT * FROM domains WHERE id = ?", (record["id"],)).fetchone()
    conn.close()
    return True, ("UPDATED" if changed else "NOCHANGE"), dict(updated_row)


def get_recent_logs(limit: int = 50) -> List[Dict]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM ip_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]
