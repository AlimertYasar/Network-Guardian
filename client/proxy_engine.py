"""
Network Guardian - Proxy Filtreleme Motoru (mitmproxy addon)
==============================================================
mitmproxy'nin "addon" olarak yüklenir. Her isteği `request` hook'unda yakalayıp
whitelist'e göre geçirir veya bloklar.

Çalıştırma (client bilgisayarda):
    mitmdump -s proxy_engine.py -p 8080

Sonra Windows sistem proxy'si 127.0.0.1:8080'e ayarlanır (kurulum scripti yapacak).
HTTPS için mitmproxy'nin sertifikası Windows trust store'a eklenmeli
(http://mitm.it adresinden indirilir veya kurulum scripti ile otomatik).

Not: Bu modül mitmproxy tarafından yüklendiği için kendi process'imizde değil,
mitmdump process'inde çalışır. Agent ile haberleşmek için yerel TCP soketi
kullanırız (agent ayrı process'te dinler) - ama basitlik için doğrudan
SharedWhitelist dosyasını polling ile okuruz, ve log'ları küçük bir
TCP loopback üzerinden agent'a gönderirken onu da agent'ın HTTP veya
soket köprüsüyle yapacağız.

Şimdilik en basit yaklaşım:
  - Whitelist'i SharedWhitelist (~/.network_guardian/whitelist.json) dosyasından
    okur ve disk modtime değişince yeniden yükler.
  - Engelleme/ziyaret loglarını yerel bir loopback portuna yazar (agent dinler).
"""

from __future__ import annotations

import json
import logging
import socket
import struct
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

# mitmproxy import - addon olarak yüklendiğinde mevcut
from mitmproxy import http  # type: ignore

logger = logging.getLogger("guardian.proxy")

WHITELIST_FILE = Path.home() / ".network_guardian" / "whitelist.json"
AGENT_LOG_PORT = 9010   # agent bu portta dinler (proxy <-> agent köprüsü)


# Engelleme sayfası HTML (kullanıcıya gösterilir)
BLOCKED_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>Erişim Engellendi</title>
<style>
  body {{
    font-family: -apple-system, Segoe UI, sans-serif;
    background: #1e1e2e; color: #cdd6f4;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; margin: 0;
  }}
  .card {{
    background: #313244; padding: 40px 50px; border-radius: 12px;
    max-width: 540px; box-shadow: 0 10px 30px rgba(0,0,0,0.4);
  }}
  h1 {{ color: #f38ba8; margin-top: 0; }}
  .domain {{
    background: #1e1e2e; padding: 8px 14px; border-radius: 6px;
    font-family: monospace; color: #fab387;
  }}
  .hint {{ color: #a6adc8; font-size: 14px; margin-top: 20px; }}
  .icon {{ font-size: 64px; text-align: center; margin-bottom: 10px; }}
</style>
</head>
<body>
  <div class="card">
    <div class="icon">🛡️</div>
    <h1>Erişim Engellendi</h1>
    <p>Aşağıdaki adrese erişim ağ politikanız tarafından engellenmiştir:</p>
    <p class="domain">{domain}</p>
    <p class="hint">
      Bu siteye erişim talebinde bulunmak için sistem tepsisindeki
      <strong>Network Guardian</strong> simgesine sağ tıklayıp
      "Erişim İste" seçeneğini kullanın.
    </p>
    <p class="hint">İstek ID: <code>{rid}</code></p>
  </div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Whitelist (sıcak yeniden yükleme ile)
# ---------------------------------------------------------------------------
class WhitelistCache:
    """Disk dosyasını polling'le okur. mitmproxy ile aynı process içindedir."""

    def __init__(self, path: Path = WHITELIST_FILE):
        self.path = path
        self._domains: set[str] = set()
        self._mtime: float = 0.0
        self._reload()

    def _reload(self) -> None:
        try:
            mt = self.path.stat().st_mtime
            if mt == self._mtime:
                return
            self._domains = set(json.loads(self.path.read_text("utf-8")))
            self._mtime = mt
            logger.info("Whitelist yeniden yüklendi: %d domain", len(self._domains))
        except (OSError, json.JSONDecodeError):
            self._domains = set()

    def is_allowed(self, host: str) -> bool:
        self._reload()
        host = host.lower().strip()
        if host in self._domains:
            return True
        # Subdomain eşleşmesi
        parts = host.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self._domains:
                return True
        return False


# ---------------------------------------------------------------------------
# Agent köprüsü (loglar için)
# ---------------------------------------------------------------------------
class AgentBridge:
    """
    Proxy <-> agent arası küçük TCP köprüsü.
    Aynı protokol formatını (length-prefix + JSON) kullanırız.
    """

    LENGTH = struct.Struct("!I")

    def __init__(self, port: int = AGENT_LOG_PORT):
        self.port = port

    def send_event(self, event_type: str, payload: dict) -> None:
        """'visit' veya 'block' eventi gönder. Sessizce başarısız olabilir."""
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=1.0) as s:
                body = json.dumps({
                    "event": event_type,
                    "payload": payload,
                    "ts": time.time(),
                }, ensure_ascii=False).encode("utf-8")
                s.sendall(self.LENGTH.pack(len(body)) + body)
        except OSError:
            # Agent çalışmıyor olabilir - log'u kaybetmek tercih edilir,
            # proxy'yi bloklamaktan iyidir
            pass


# ---------------------------------------------------------------------------
# mitmproxy addon
# ---------------------------------------------------------------------------
class GuardianAddon:
    """
    mitmproxy bu sınıfın bir örneğini bulur ve hook'larını çağırır.
    """

    def __init__(self):
        self.whitelist = WhitelistCache()
        self.bridge = AgentBridge()

    def _domain_of(self, flow: http.HTTPFlow) -> str:
        # CONNECT (HTTPS tunnel) için flow.request.host doğru bilgi
        return (flow.request.host or "").lower()

    def request(self, flow: http.HTTPFlow) -> None:
        """Her HTTP isteğinde çalışır. HTTPS'de SNI sayesinde host bilinir."""
        domain = self._domain_of(flow)
        if not domain:
            return

        if self.whitelist.is_allowed(domain):
            self.bridge.send_event("visit", {
                "domain": domain,
                "url": flow.request.pretty_url,
                "method": flow.request.method,
                "bytes": len(flow.request.content or b""),
            })
            return

        # Engelle - kullanıcıya açıklayıcı sayfa göster
        rid = f"{int(time.time())}-{flow.id[:8]}"
        flow.response = http.Response.make(
            403,
            BLOCKED_HTML_TEMPLATE.format(domain=domain, rid=rid).encode("utf-8"),
            {"Content-Type": "text/html; charset=utf-8"},
        )
        self.bridge.send_event("block", {
            "domain": domain,
            "url": flow.request.pretty_url,
            "method": flow.request.method,
        })

    def response(self, flow: http.HTTPFlow) -> None:
        """Yanıt boyutunu visit log'una eklemek için."""
        if flow.response and flow.response.status_code != 403:
            domain = self._domain_of(flow)
            if self.whitelist.is_allowed(domain):
                self.bridge.send_event("visit_response", {
                    "domain": domain,
                    "bytes": len(flow.response.content or b""),
                })


# mitmproxy bu listeyi tarar
addons = [GuardianAddon()]
