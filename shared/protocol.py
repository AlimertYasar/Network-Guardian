"""
Network Guardian - Ortak Protokol
==================================
Client ve Server arasındaki TCP iletişim formatını tanımlar.

Mesaj formatı (hattaki yapı):
    [4 byte length prefix (big-endian uint32)] [JSON payload (UTF-8)]

JSON payload yapısı:
    {
        "cmd": "<komut adı>",
        "client_id": "<client UUID veya hostname>",
        "timestamp": <unix epoch>,
        "data": { ... komuta özel alanlar ... }
    }
"""

from __future__ import annotations

import json
import socket
import struct
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Komut sabitleri
# ---------------------------------------------------------------------------
class Command(str, Enum):
    """Tüm geçerli komut türleri. String enum kullandık ki JSON'a doğrudan yazılabilsin."""

    # --- Client -> Server ---
    REGISTER = "REGISTER"                # Client ilk bağlandığında kendini tanıtır
    HEARTBEAT = "HEARTBEAT"              # Client hâlâ aktif, periyodik
    REQUEST_ACCESS = "REQUEST_ACCESS"    # Engellenmiş bir siteye erişim talebi
    LOG_VISIT = "LOG_VISIT"              # Bir site ziyaret edildi (özet)
    LOG_BLOCK = "LOG_BLOCK"              # Engellenen bir istek
    USAGE_REPORT = "USAGE_REPORT"        # Periyodik kullanım özeti

    # --- Server -> Client ---
    ACK = "ACK"                                  # Genel onay
    WHITELIST_UPDATE = "WHITELIST_UPDATE"        # Whitelist'in tamamı / güncellemesi
    WHITELIST_ADD = "WHITELIST_ADD"              # Tek domain ekleme
    WHITELIST_REMOVE = "WHITELIST_REMOVE"        # Tek domain çıkarma
    REQUEST_DECISION = "REQUEST_DECISION"        # Talebine onay/red cevabı
    FORCE_DISCONNECT = "FORCE_DISCONNECT"        # Yönetici client'ı internetten kesti
    SHUTDOWN = "SHUTDOWN"                        # Test/bakım amaçlı


class Decision(str, Enum):
    """Erişim talebi kararları."""
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    PENDING = "PENDING"


# ---------------------------------------------------------------------------
# Mesaj sınıfı
# ---------------------------------------------------------------------------
@dataclass
class Message:
    """
    Tüm trafiği taşıyan kapsayıcı.

    `cmd` Command enum string değeridir. `data` komuta özel sözlüktür.
    """
    cmd: str
    client_id: str = ""
    timestamp: float = field(default_factory=time.time)
    data: dict[str, Any] = field(default_factory=dict)

    def to_json_bytes(self) -> bytes:
        return json.dumps(asdict(self), ensure_ascii=False).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, raw: bytes) -> "Message":
        obj = json.loads(raw.decode("utf-8"))
        return cls(
            cmd=obj.get("cmd", ""),
            client_id=obj.get("client_id", ""),
            timestamp=obj.get("timestamp", time.time()),
            data=obj.get("data", {}),
        )


# ---------------------------------------------------------------------------
# Düşük seviyeli send/recv helpers (length-prefixed framing)
# ---------------------------------------------------------------------------
LENGTH_HEADER = struct.Struct("!I")   # 4 byte big-endian unsigned int
MAX_MESSAGE_BYTES = 16 * 1024 * 1024  # 16 MB güvenlik üst sınırı


def send_message(sock: socket.socket, msg: Message) -> None:
    """
    Bir Message nesnesini sokete gönderir.
    Önce 4 byte uzunluk, sonra JSON gövdesi yazılır.
    """
    payload = msg.to_json_bytes()
    if len(payload) > MAX_MESSAGE_BYTES:
        raise ValueError(f"Mesaj çok büyük: {len(payload)} byte")
    header = LENGTH_HEADER.pack(len(payload))
    # sendall hata durumunda exception fırlatır - çağıran yakalamalı
    sock.sendall(header + payload)


def recv_exactly(sock: socket.socket, n: int) -> bytes:
    """
    Tam olarak n byte okur. Bağlantı düşerse ConnectionError fırlatır.
    socket.recv parça parça gelebileceği için döngü gerekli.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Karşı taraf bağlantıyı kapattı")
        buf.extend(chunk)
    return bytes(buf)


def recv_message(sock: socket.socket) -> Message:
    """Soketten bir Message okur (length-prefixed)."""
    header = recv_exactly(sock, LENGTH_HEADER.size)
    (length,) = LENGTH_HEADER.unpack(header)
    if length == 0 or length > MAX_MESSAGE_BYTES:
        raise ValueError(f"Geçersiz mesaj boyutu: {length}")
    body = recv_exactly(sock, length)
    return Message.from_json_bytes(body)


# ---------------------------------------------------------------------------
# Yardımcı fabrika fonksiyonları (hızlı mesaj üretimi için)
# ---------------------------------------------------------------------------
def make_register(client_id: str, hostname: str, username: str) -> Message:
    return Message(
        cmd=Command.REGISTER.value,
        client_id=client_id,
        data={"hostname": hostname, "username": username, "version": "0.1.0"},
    )


def make_heartbeat(client_id: str) -> Message:
    return Message(cmd=Command.HEARTBEAT.value, client_id=client_id)


def make_request_access(client_id: str, url: str, domain: str, reason: str = "") -> Message:
    return Message(
        cmd=Command.REQUEST_ACCESS.value,
        client_id=client_id,
        data={
            "request_id": str(uuid.uuid4()),
            "url": url,
            "domain": domain,
            "reason": reason,
        },
    )


def make_log_visit(client_id: str, domain: str, url: str, bytes_xfer: int) -> Message:
    return Message(
        cmd=Command.LOG_VISIT.value,
        client_id=client_id,
        data={"domain": domain, "url": url, "bytes": bytes_xfer},
    )


def make_log_block(client_id: str, domain: str, url: str) -> Message:
    return Message(
        cmd=Command.LOG_BLOCK.value,
        client_id=client_id,
        data={"domain": domain, "url": url},
    )


def make_whitelist_update(domains: list[str]) -> Message:
    return Message(
        cmd=Command.WHITELIST_UPDATE.value,
        data={"domains": domains},
    )


def make_request_decision(request_id: str, decision: Decision, note: str = "") -> Message:
    return Message(
        cmd=Command.REQUEST_DECISION.value,
        data={"request_id": request_id, "decision": decision.value, "note": note},
    )


def make_ack(reference: str = "") -> Message:
    return Message(cmd=Command.ACK.value, data={"ref": reference})
