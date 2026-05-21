"""
Network Guardian - Komut Sunucusu
==================================
TCP/JSON tabanlı multi-client sunucu.

Her client için ayrı bir thread çalışır. Server şunları yapar:
  - Client REGISTER alınca DB'ye kaydeder, whitelist'i geri gönderir
  - HEARTBEAT alınca last_seen günceller
  - REQUEST_ACCESS alınca AI'a değerlendirtir, DB'ye PENDING yazar,
    yöneticinin paneline sinyal verir
  - LOG_VISIT / LOG_BLOCK loglarını DB'ye yazar
  - Yönetici karar verince WHITELIST_ADD / REQUEST_DECISION mesajı gönderir

PyQt arayüzüne sinyal göndermek için "callback" mekanizması kullanılır:
admin_app sunucuyu kurarken kendi event handler'larını kaydeder.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

# Üst paketten import için path düzeltmesi (server/ altından çalıştırıldığında)
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shared.protocol import (
    Command, Decision, Message,
    send_message, recv_message,
    make_ack, make_whitelist_update, make_request_decision,
)
from server.database import get_db, Database
from server.ai import get_evaluator, OllamaEvaluator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Bağlı client temsili
# ---------------------------------------------------------------------------
@dataclass
class ConnectedClient:
    client_id: str
    hostname: str
    address: tuple[str, int]
    sock: socket.socket
    username: str = ""
    last_seen: float = field(default_factory=time.time)
    send_lock: threading.Lock = field(default_factory=threading.Lock)

    def send(self, msg: Message) -> bool:
        """Thread-safe gönderim. Hata olursa False döner."""
        try:
            with self.send_lock:
                send_message(self.sock, msg)
            return True
        except (OSError, ConnectionError) as e:
            logger.warning("Client %s'e gönderim başarısız: %s", self.client_id, e)
            return False


# ---------------------------------------------------------------------------
# Sunucu
# ---------------------------------------------------------------------------
class CommandServer:
    """
    Multi-client TCP sunucusu.

    UI'ya bilgi vermek için event callback'leri:
        on_client_connected(client)
        on_client_disconnected(client_id)
        on_access_request(request_row)   # DB satırı (AI değerlendirmesi tamamlanmış)
        on_log_event(client_id, event_type, data)
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 9009,
        db: Optional[Database] = None,
        evaluator: Optional[OllamaEvaluator] = None,
    ):
        self.host = host
        self.port = port
        self.db = db or get_db()
        self.evaluator = evaluator or get_evaluator()

        self._server_sock: Optional[socket.socket] = None
        self._running = False
        self._accept_thread: Optional[threading.Thread] = None

        # client_id -> ConnectedClient
        self._clients: dict[str, ConnectedClient] = {}
        self._clients_lock = threading.RLock()

        # Event callback'leri (UI'dan kaydedilir)
        self.on_client_connected: Optional[Callable[[ConnectedClient], None]] = None
        self.on_client_disconnected: Optional[Callable[[str], None]] = None
        self.on_access_request: Optional[Callable[[dict], None]] = None
        self.on_log_event: Optional[Callable[[str, str, dict], None]] = None

    # -----------------------------------------------------------------
    # Yaşam döngüsü
    # -----------------------------------------------------------------
    def start(self) -> None:
        if self._running:
            return
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(64)
        self._running = True
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="cmd-server-accept", daemon=True
        )
        self._accept_thread.start()
        logger.info("Komut sunucusu %s:%d adresinde dinliyor", self.host, self.port)

    def stop(self) -> None:
        self._running = False
        # Tüm bağlı client soketlerini kapat
        with self._clients_lock:
            for c in list(self._clients.values()):
                try:
                    c.sock.close()
                except OSError:
                    pass
            self._clients.clear()
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None
        logger.info("Komut sunucusu durduruldu")

    # -----------------------------------------------------------------
    # Kabul döngüsü ve client thread'leri
    # -----------------------------------------------------------------
    def _accept_loop(self) -> None:
        assert self._server_sock is not None
        while self._running:
            try:
                client_sock, addr = self._server_sock.accept()
            except OSError:
                if self._running:
                    logger.exception("Accept hatası")
                break
            # Her client için ayrı thread
            t = threading.Thread(
                target=self._client_loop,
                args=(client_sock, addr),
                name=f"client-{addr[0]}:{addr[1]}",
                daemon=True,
            )
            t.start()

    def _client_loop(self, sock: socket.socket, addr: tuple[str, int]) -> None:
        """Tek bir client'la olan iletişimi yönetir."""
        client: Optional[ConnectedClient] = None
        try:
            # İlk mesaj REGISTER olmalı
            first = recv_message(sock)
            if first.cmd != Command.REGISTER.value:
                logger.warning("İlk mesaj REGISTER değil, bağlantı kapatılıyor: %s", addr)
                sock.close()
                return

            client = ConnectedClient(
                client_id=first.client_id,
                hostname=first.data.get("hostname", "?"),
                address=addr,
                sock=sock,
                username=first.data.get("username", ""),
            )
            with self._clients_lock:
                # Aynı client_id ile eski bağlantı varsa kapat
                old = self._clients.pop(client.client_id, None)
                if old:
                    try:
                        old.sock.close()
                    except OSError:
                        pass
                self._clients[client.client_id] = client

            self.db.upsert_client(client.client_id, client.hostname, addr[0])
            logger.info(
                "Client REGISTER: %s (%s) %s",
                client.client_id, client.hostname, addr,
            )

            # ACK + güncel whitelist'i hemen gönder
            client.send(make_ack("registered"))
            client.send(make_whitelist_update(self.db.get_whitelist()))

            if self.on_client_connected:
                self._safe_callback(self.on_client_connected, client)

            # Mesaj alma döngüsü
            while self._running:
                msg = recv_message(sock)
                client.last_seen = time.time()
                self._handle_message(client, msg)

        except (ConnectionError, OSError, ValueError) as e:
            logger.info("Client bağlantısı sonlandı (%s): %s", addr, e)
        except Exception:
            logger.exception("Client thread'inde beklenmeyen hata")
        finally:
            if client:
                with self._clients_lock:
                    self._clients.pop(client.client_id, None)
                self.db.mark_client_offline(client.client_id)
                if self.on_client_disconnected:
                    self._safe_callback(self.on_client_disconnected, client.client_id)
            try:
                sock.close()
            except OSError:
                pass

    # -----------------------------------------------------------------
    # Mesaj yönlendirme
    # -----------------------------------------------------------------
    def _handle_message(self, client: ConnectedClient, msg: Message) -> None:
        cmd = msg.cmd
        if cmd == Command.HEARTBEAT.value:
            self.db.touch_client(client.client_id)

        elif cmd == Command.REQUEST_ACCESS.value:
            self._handle_access_request(client, msg)

        elif cmd == Command.LOG_VISIT.value:
            d = msg.data
            self.db.log_visit(
                client_id=client.client_id,
                username=client.username,
                domain=d.get("domain", ""),
                url=d.get("url", ""),
                bytes_xfer=int(d.get("bytes", 0)),
            )
            if self.on_log_event:
                self._safe_callback(self.on_log_event, client.client_id, "visit", d)

        elif cmd == Command.LOG_BLOCK.value:
            d = msg.data
            self.db.log_block(
                client_id=client.client_id,
                username=client.username,
                domain=d.get("domain", ""),
                url=d.get("url", ""),
            )
            if self.on_log_event:
                self._safe_callback(self.on_log_event, client.client_id, "block", d)

        elif cmd == Command.USAGE_REPORT.value:
            # İleride toplu rapor için
            pass

        else:
            logger.debug("Bilinmeyen komut: %s", cmd)

    def _handle_access_request(self, client: ConnectedClient, msg: Message) -> None:
        """Client'tan gelen erişim talebini işle: DB'ye yaz, AI'a sor, UI'ya bildir."""
        d = msg.data
        request_id = d.get("request_id", "")
        url = d.get("url", "")
        domain = d.get("domain", "")
        reason = d.get("reason", "")

        if not request_id or not domain:
            logger.warning("Geçersiz REQUEST_ACCESS: %s", d)
            return

        # Önce DB'ye yaz (PENDING)
        self.db.insert_access_request(
            request_id=request_id,
            client_id=client.client_id,
            username=client.username,
            url=url,
            domain=domain,
            reason=reason,
        )
        client.send(make_ack(request_id))

        # AI değerlendirmesi (background thread - UI'yi bloklasın istemiyoruz)
        threading.Thread(
            target=self._evaluate_in_background,
            args=(request_id, url, domain, reason),
            daemon=True,
            name=f"ai-eval-{request_id[:8]}",
        ).start()

    def _evaluate_in_background(
        self, request_id: str, url: str, domain: str, reason: str
    ) -> None:
        verdict = self.evaluator.evaluate(url, domain, reason)
        self.db.update_request_ai(
            request_id=request_id,
            verdict=verdict.verdict,
            reason=verdict.reason,
            score=verdict.score,
        )
        # UI'ya bildir
        row = self.db.get_request(request_id)
        if row and self.on_access_request:
            self._safe_callback(self.on_access_request, dict(row))

    # -----------------------------------------------------------------
    # Yöneticiden gelen aksiyonlar (admin app çağırır)
    # -----------------------------------------------------------------
    def approve_request(self, request_id: str, admin_note: str = "") -> bool:
        """Yönetici talebi onayladı. DB güncelle, whitelist'e ekle, client'a haber ver."""
        row = self.db.get_request(request_id)
        if not row:
            return False
        self.db.decide_request(request_id, Decision.APPROVED.value, admin_note)
        self.db.add_to_whitelist(row["domain"], added_by="admin", note=admin_note)

        # Tüm client'lara whitelist güncellemesi gönder
        self.broadcast_whitelist()

        # İlgili client'a karar mesajı gönder
        with self._clients_lock:
            client = self._clients.get(row["client_id"])
        if client:
            client.send(make_request_decision(request_id, Decision.APPROVED, admin_note))
        return True

    def reject_request(self, request_id: str, admin_note: str = "") -> bool:
        row = self.db.get_request(request_id)
        if not row:
            return False
        self.db.decide_request(request_id, Decision.REJECTED.value, admin_note)
        with self._clients_lock:
            client = self._clients.get(row["client_id"])
        if client:
            client.send(make_request_decision(request_id, Decision.REJECTED, admin_note))
        return True

    def add_whitelist_domain(self, domain: str, note: str = "") -> None:
        """Yönetici manuel olarak whitelist'e ekledi."""
        self.db.add_to_whitelist(domain, added_by="admin", note=note)
        self.broadcast_whitelist()

    def remove_whitelist_domain(self, domain: str) -> None:
        self.db.remove_from_whitelist(domain)
        self.broadcast_whitelist()

    def broadcast_whitelist(self) -> None:
        msg = make_whitelist_update(self.db.get_whitelist())
        with self._clients_lock:
            clients = list(self._clients.values())
        for c in clients:
            c.send(msg)

    def force_disconnect_client(self, client_id: str) -> bool:
        """Yönetici bir client'ı internetten kesti."""
        with self._clients_lock:
            client = self._clients.get(client_id)
        if not client:
            return False
        msg = Message(cmd=Command.FORCE_DISCONNECT.value, data={})
        client.send(msg)
        return True

    # -----------------------------------------------------------------
    # Yardımcılar
    # -----------------------------------------------------------------
    def list_connected(self) -> list[ConnectedClient]:
        with self._clients_lock:
            return list(self._clients.values())

    @staticmethod
    def _safe_callback(cb: Callable, *args) -> None:
        try:
            cb(*args)
        except Exception:
            logger.exception("Callback hatası")


# ---------------------------------------------------------------------------
# Doğrudan çalıştırma (test/debug için)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(threadName)s] %(levelname)s %(name)s: %(message)s",
    )
    server = CommandServer()
    server.start()
    print(f"Komut sunucusu başlatıldı: port {server.port}")
    print("Çıkmak için Ctrl+C")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nKapatılıyor...")
        server.stop()
