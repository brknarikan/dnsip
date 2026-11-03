import os
import platform
import plistlib
import subprocess
import sys
from typing import Tuple

APP_NAME = "DNSIPClient"
MACOS_LABEL = "com.dnsip.client"


def get_launch_command(minimized: bool = True) -> list:
    """Çalıştırılabilir dosya (.exe / .app) veya Python betiği komutunu döner."""
    arg = "--minimized" if minimized else ""
    if getattr(sys, "frozen", False):
        # PyInstaller ile derlenmiş tek dosya (.exe veya macOS binary)
        cmd = [sys.executable]
    else:
        script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "ddns_client.py"))
        python_exe = sys.executable
        # Windows'ta konsol penceresi açılmaması için pythonw.exe varsa onu tercih et
        if platform.system() == "Windows" and python_exe.lower().endswith("python.exe"):
            pythonw = python_exe[:-10] + "pythonw.exe"
            if os.path.exists(pythonw):
                python_exe = pythonw
        cmd = [python_exe, script_path]

    if arg:
        cmd.append(arg)
    return cmd


def is_autostart_enabled() -> bool:
    system = platform.system()
    if system == "Windows":
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_READ,
            )
            val, _ = winreg.QueryValueEx(key, APP_NAME)
            winreg.CloseKey(key)
            return bool(val)
        except Exception:
            return False

    elif system == "Darwin":  # macOS
        plist_path = os.path.expanduser(f"~/Library/LaunchAgents/{MACOS_LABEL}.plist")
        return os.path.exists(plist_path)

    return False


def set_autostart(enable: bool) -> Tuple[bool, str]:
    system = platform.system()
    cmd_list = get_launch_command(minimized=True)

    if system == "Windows":
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_SET_VALUE,
            )
            if enable:
                cmd_str = " ".join(f'"{part}"' for part in cmd_list)
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, cmd_str)
                winreg.CloseKey(key)
                return True, "Windows başlangıcında otomatik çalışma aktif edildi."
            else:
                try:
                    winreg.DeleteValue(key, APP_NAME)
                except FileNotFoundError:
                    pass
                winreg.CloseKey(key)
                return True, "Windows başlangıcında otomatik çalışma kapatıldı."
        except Exception as exc:
            return False, f"Windows Registry hatası: {exc}"

    elif system == "Darwin":  # macOS
        plist_dir = os.path.expanduser("~/Library/LaunchAgents")
        plist_path = os.path.join(plist_dir, f"{MACOS_LABEL}.plist")
        try:
            if enable:
                os.makedirs(plist_dir, exist_ok=True)
                plist_content = {
                    "Label": MACOS_LABEL,
                    "ProgramArguments": cmd_list,
                    "RunAtLoad": True,
                    "KeepAlive": False,
                    "WorkingDirectory": os.path.dirname(os.path.abspath(__file__)),
                }
                with open(plist_path, "wb") as fp:
                    plistlib.dump(plist_content, fp)
                subprocess.run(["launchctl", "load", plist_path], check=False)
                return True, "macOS LaunchAgent (Otomatik Başlatma) aktif edildi."
            else:
                if os.path.exists(plist_path):
                    subprocess.run(["launchctl", "unload", plist_path], check=False)
                    os.remove(plist_path)
                return True, "macOS LaunchAgent kaldırıldı."
        except Exception as exc:
            return False, f"macOS LaunchAgent hatası: {exc}"

    else:
        return False, f"{system} için otomatik başlatma systemd/cron ile yapılandırılabilir."
