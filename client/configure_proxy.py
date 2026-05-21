"""
Network Guardian - Windows Sistem Proxy Yapılandırıcı
======================================================
Windows'un internet ayarlarındaki proxy'sini Network Guardian'ın yerel
mitmproxy'sine (127.0.0.1:8080) yönlendirir.

Bu işlemler kayıt defterini değiştirir, yönetici izni gerekir.

Kullanım:
    python configure_proxy.py enable
    python configure_proxy.py disable
    python configure_proxy.py status

NOT: HTTPS interception için mitmproxy sertifikasını ayrıca güvenilir
köke eklemek gerekir. mitmdump ilk çalıştığında ~/.mitmproxy/mitmproxy-ca-cert.cer
dosyasını üretir. Bunu yüklemek için:
    certutil -addstore -f "ROOT" %USERPROFILE%\\.mitmproxy\\mitmproxy-ca-cert.cer
"""

from __future__ import annotations

import argparse
import sys
import platform


PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080


def _get_winreg():
    if platform.system() != "Windows":
        print("[!] Bu script yalnızca Windows'ta çalışır.")
        sys.exit(1)
    import winreg  # type: ignore
    return winreg


INTERNET_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def enable() -> None:
    winreg = _get_winreg()
    proxy = f"{PROXY_HOST}:{PROXY_PORT}"
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, INTERNET_KEY, 0, winreg.KEY_WRITE
    ) as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy)
        # Yerel adresleri proxy'lemeyelim
        winreg.SetValueEx(
            key, "ProxyOverride", 0, winreg.REG_SZ,
            "localhost;127.0.0.1;<local>"
        )
    _refresh_internet_settings()
    print(f"[✓] Sistem proxy'si etkinleştirildi: {proxy}")


def disable() -> None:
    winreg = _get_winreg()
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, INTERNET_KEY, 0, winreg.KEY_WRITE
    ) as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
    _refresh_internet_settings()
    print("[✓] Sistem proxy'si devre dışı bırakıldı.")


def status() -> None:
    winreg = _get_winreg()
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, INTERNET_KEY, 0, winreg.KEY_READ
    ) as key:
        try:
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
        except FileNotFoundError:
            enabled = 0
        try:
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
        except FileNotFoundError:
            server = ""
    print(f"Proxy aktif: {'evet' if enabled else 'hayır'}")
    print(f"Proxy adresi: {server or '-'}")


def _refresh_internet_settings() -> None:
    """WinINet'e ayar değiştiğini bildir (yeniden başlatmaya gerek kalmasın)."""
    try:
        import ctypes
        from ctypes import wintypes
        InternetSetOption = ctypes.windll.Wininet.InternetSetOptionW
        INTERNET_OPTION_SETTINGS_CHANGED = 39
        INTERNET_OPTION_REFRESH = 37
        InternetSetOption(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        InternetSetOption(0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception as e:
        print(f"[!] Internet ayarları yenilenemedi: {e}")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=["enable", "disable", "status"])
    args = p.parse_args()
    {"enable": enable, "disable": disable, "status": status}[args.action]()
    return 0


if __name__ == "__main__":
    sys.exit(main())
