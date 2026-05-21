"""
Network Guardian - Client Agent
================================
Her client bilgisayarda çalışan ana arka plan servisi.

Görevler:
  - Sunucuya TCP bağlantısı kur ve REGISTER ol
  - Periyodik HEARTBEAT gönder
  - Sunucudan WHITELIST_UPDATE alınca yerel whitelist'i güncelle
    (proxy_engine bu listeyi okuyarak filtreleme yapar)
  - Tray UI'dan gelen erişim taleplerini sunucuya ilet
  - REQUEST_DECISION cevabı gelince UI'ya bildir
  - Bağlantı kopuşunda otomatik yeniden bağlan

Whitelist'i proxy ile paylaşmak için thread-safe bir SharedWhitelist sınıfı kullanırız.
Proxy ayrı bir process'te çalıştığı için bunu bir dosyaya da yazarız (atomik).
"""

from __future__ import annotations

import getpass
import json
import logging
import socket
import sys
import threading
import time
import uuid
from pathlib import Path
from queue import Queue, Empty
from typing import Callable, Optional

# Üst paketten import
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared.protocol import (
    Command, Message,
    send_message, recv_message,
    make_register, make_heartbeat, make_request_access,
    make_log_visit, make_log_block,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Yerel whitelist - proxy ve agent arasında paylaşılan veri
# ---------------------------------------------------------------------------
WHITELIST_FILE = Path.home() / ".network_guardian" / "whitelist.json"
CLIENT_ID_FILE = Path.home() / ".network_guardian" / "client_id"


class SharedWhitelist:
    """
    Hem agent thread'inden hem proxy process'inden erişilebilen whitelist.

    İki katmanlı:
      - Bellek içi set (hızlı kontrol için)
      - Disk dosyası (proxy ayrı process olabileceği için)
    """

    def __init__(self, file_path: Path = WHITELIST_FILE):
        self.file_path = file_path
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._domains: set[str] = set()
        self.load()

    def load(self) -> None:
        with self._lock:
            if self.file_path.exists():
                try:
                    self._domains = set(json.loads(self.file_path.read_text("utf-8")))
                except (json.JSONDecodeError, OSError):
                    self._domains = set()

    def update(self, domains: list[str]) -> None:
        with self._lock:
            self._domains = {d.lower().strip() for d in domains if d}
            # Atomik yazım: önce .tmp'ye yaz, sonra rename
            tmp = self.file_path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps(sorted(self._domains), ensure_ascii=False),
                encoding="utf-8",
            )
            tmp.replace(self.file_path)

    def is_allowed(self, domain: str) -> bool:
        domain = domain.lower().strip()
        with self._lock:
            if domain in self._domains:
                return True
            # Subdomain eşleşmesi: mail.google.com -> google.com varsa OK
            parts = domain.split(".")
            for i in range(1, len(parts) - 1):
                if ".".join(parts[i:]) in self._domains:
                    return True
            return False

    def all(self) -> list[str]:
        with self._lock:
            return sorted(self._domains)


# ---------------------------------------------------------------------------
# Client kimliği
# ---------------------------------------------------------------------------
def get_or_create_client_id() -> str:
    """Kalıcı bir client UUID'si oluştur/oku."""
    CLIENT_ID_FILE.parent.mkdir(parents=True, exist_ok=True)
    if CLIENT_ID_FILE.exists():
        cid = CLIENT_ID_FILE.read_text("utf-8").strip()
        if cid:
            return cid
    cid = str(uuid.uuid4())
    CLIENT_ID_FILE.write_text(cid, encoding="utf-8")
    return cid


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------
class ClientAgent:
    """Sunucuyla TCP üzerinden konuşan ana ajan."""

    HEARTBEAT_INTERVAL = 30        # saniye
    RECONNECT_DELAY = 5            # saniye

    def __init__(
        self,
        server_host: str,
        server_port: int = 9009,
        whitelist: Optional[SharedWhitelist] = None,
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.whitelist = whitelist or SharedWhitelist()

        self.client_id = get_or_create_client_id()
        self.hostname = socket.gethostname()
        self.username = getpass.getuser()

        self._sock: Optional[socket.socket] = None
        self._running = False
        self._send_lock = threading.Lock()
        self._send_queue: Queue[Message] = Queue()

        # UI'dan gelecek erişim cevaplarını dinlemek için callback
        self.on_decision: Optional[Callable[[dict], None]] = None
        self.on_connected: Optional[Callable[[], None]] = None
        self.on_disconnected: Optional[Callable[[], None]] = None

        self._threads: list[threading.Thread] = []

    # -----------------------------------------------------------------
    # Yaşam döngüsü
    # -----------------------------------------------------------------
    def start(self) -> None:
        if self._running:
            return
        self._running = True
        # Ana bağlantı/yeniden bağlantı döngüsü
        t = threading.Thread(target=self._connection_loop, name="agent-conn", daemon=True)
        t.start()
        self._threads.append(t)
        logger.info(
            "ClientAgent başlatıldı (id=%s host=%s user=%s)",
            self.client_id, self.hostname, self.username,
        )

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    # -----------------------------------------------------------------
    # Proxy köprüsü - mitmproxy addon'undan log eventi alır
    # -----------------------------------------------------------------
    def start_proxy_bridge(self, port: int = 9010) -> None:
        """mitmproxy addon'unun gönderdiği visit/block event'lerini dinler."""
        t = threading.Thread(
            target=self._proxy_bridge_loop, args=(port,),
            name="proxy-bridge", daemon=True,
        )
        t.start()
        self._threads.append(t)

    def _proxy_bridge_loop(self, port: int) -> None:
        import struct
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("127.0.0.1", port))
        except OSError as e:
            logger.error("Proxy köprüsü portu açılamadı: %s", e)
            return
        srv.listen(32)
        srv.settimeout(0.5)
        logger.info("Proxy köprüsü 127.0.0.1:%d adresinde dinliyor", port)
        length_struct = struct.Struct("!I")

        while self._running:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(2)
                hdr = conn.recv(length_struct.size)
                if len(hdr) != length_struct.size:
                    conn.close()
                    continue
                (n,) = length_struct.unpack(hdr)
                if n <= 0 or n > 1_000_000:
                    conn.close()
                    continue
                buf = b""
                while len(buf) < n:
                    chunk = conn.recv(n - len(buf))
                    if not chunk:
                        break
                    buf += chunk
                conn.close()
                if len(buf) != n:
                    continue
                evt = json.loads(buf.decode("utf-8"))
                self._handle_proxy_event(evt)
            except (OSError, json.JSONDecodeError):
                try:
                    conn.close()
                except OSError:
                    pass

        try:
            srv.close()
        except OSError:
            pass

    def _handle_proxy_event(self, evt: dict) -> None:
        et = evt.get("event")
        p = evt.get("payload", {})
        if et == "visit":
            self.report_visit(
                p.get("domain", ""), p.get("url", ""), int(p.get("bytes", 0))
            )
        elif et == "visit_response":
            self.report_visit(
                p.get("domain", ""), "", int(p.get("bytes", 0))
            )
        elif et == "block":
            self.report_block(p.get("domain", ""), p.get("url", ""))

    # -----------------------------------------------------------------
    # Bağlantı yönetimi
    # -----------------------------------------------------------------
    def _connection_loop(self) -> None:
        """Sürekli bağlı kalmaya çalışır. Kopuşta yeniden bağlanır."""
        while self._running:
            try:
                self._connect_and_serve()
            except Exception:
                logger.exception("Bağlantı döngüsünde hata")
            if self._running:
                logger.info("Sunucuya yeniden bağlanılacak (%ds)", self.RECONNECT_DELAY)
                time.sleep(self.RECONNECT_DELAY)

    def _connect_and_serve(self) -> None:
        """Bir bağlantı oturumu boyunca çalışır."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        try:
            sock.connect((self.server_host, self.server_port))
        except OSError as e:
            logger.warning("Sunucuya bağlanılamadı: %s", e)
            sock.close()
            return
        sock.settimeout(None)
        self._sock = sock
        logger.info("Sunucuya bağlanıldı: %s:%d", self.server_host, self.server_port)

        try:
            # REGISTER gönder
            send_message(sock, make_register(self.client_id, self.hostname, self.username))

            if self.on_connected:
                try:
                    self.on_connected()
                except Exception:
                    logger.exception("on_connected callback hatası")

            # Heartbeat ve send-queue thread'lerini başlat
            stop_event = threading.Event()
            hb = threading.Thread(
                target=self._heartbeat_loop, args=(stop_event,),
                name="agent-heartbeat", daemon=True,
            )
            sender = threading.Thread(
                target=self._send_loop, args=(stop_event,),
                name="agent-sender", daemon=True,
            )
            hb.start()
            sender.start()

            # Recv döngüsü (ana thread)
            try:
                while self._running:
                    msg = recv_message(sock)
                    self._handle_server_message(msg)
            finally:
                stop_event.set()
                hb.join(timeout=2)
                sender.join(timeout=2)

        except (ConnectionError, OSError, ValueError) as e:
            logger.info("Bağlantı koptu: %s", e)
        finally:
            try:
                sock.close()
            except OSError:
                pass
            self._sock = None
            if self.on_disconnected:
                try:
                    self.on_disconnected()
                except Exception:
                    pass

    def _heartbeat_loop(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            if stop_event.wait(self.HEARTBEAT_INTERVAL):
                break
            self._enqueue(make_heartbeat(self.client_id))

    def _send_loop(self, stop_event: threading.Event) -> None:
        """Send queue'dan mesajları sokete yazar (recv ile çakışmasın diye)."""
        while not stop_event.is_set():
            try:
                msg = self._send_queue.get(timeout=0.5)
            except Empty:
                continue
            sock = self._sock
            if sock is None:
                # Bağlantı kapanmış, mesajı geri kuyruğa koymaya gerek yok
                # (yeniden bağlanınca yeni mesajlar üretilir)
                continue
            try:
                with self._send_lock:
                    send_message(sock, msg)
            except (OSError, ConnectionError) as e:
                logger.warning("Mesaj gönderilemedi: %s", e)
                # Bağlantı kopmuş - recv tarafı da yakalayacak
                break

    # -----------------------------------------------------------------
    # Sunucudan gelen mesajların işlenmesi
    # -----------------------------------------------------------------
    def _handle_server_message(self, msg: Message) -> None:
        cmd = msg.cmd
        if cmd == Command.WHITELIST_UPDATE.value:
            domains = msg.data.get("domains", [])
            self.whitelist.update(domains)
            logger.info("Whitelist güncellendi: %d domain", len(domains))

        elif cmd == Command.WHITELIST_ADD.value:
            domain = msg.data.get("domain", "")
            if domain:
                current = set(self.whitelist.all())
                current.add(domain)
                self.whitelist.update(list(current))

        elif cmd == Command.WHITELIST_REMOVE.value:
            domain = msg.data.get("domain", "")
            if domain:
                current = set(self.whitelist.all())
                current.discard(domain)
                self.whitelist.update(list(current))

        elif cmd == Command.REQUEST_DECISION.value:
            logger.info("Karar alındı: %s", msg.data)
            if self.on_decision:
                try:
                    self.on_decision(msg.data)
                except Exception:
                    logger.exception("on_decision callback hatası")

        elif cmd == Command.FORCE_DISCONNECT.value:
            logger.warning("Yönetici tarafından internet erişimi kesildi")
            # Tüm whitelist'i boşaltarak kullanıcının her şeyini engelle
            self.whitelist.update([])

        elif cmd == Command.ACK.value:
            logger.debug("ACK: %s", msg.data)

        else:
            logger.debug("Bilinmeyen sunucu komutu: %s", cmd)

    # -----------------------------------------------------------------
    # Dış API (UI ve proxy çağırır)
    # -----------------------------------------------------------------
    def request_access(self, url: str, domain: str, reason: str = "") -> str:
        """UI'dan çağrılır: yöneticiye erişim talebi gönder."""
        msg = make_request_access(self.client_id, url, domain, reason)
        self._enqueue(msg)
        return msg.data["request_id"]

    def report_visit(self, domain: str, url: str, bytes_xfer: int = 0) -> None:
        """Proxy bir geçişi raporlar."""
        self._enqueue(make_log_visit(self.client_id, domain, url, bytes_xfer))

    def report_block(self, domain: str, url: str) -> None:
        """Proxy bir engellemeyi raporlar."""
        self._enqueue(make_log_block(self.client_id, domain, url))

    # -----------------------------------------------------------------
    def _enqueue(self, msg: Message) -> None:
        self._send_queue.put(msg)


# ---------------------------------------------------------------------------
# Doğrudan çalıştırma için (test)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9009)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(threadName)s] %(levelname)s %(name)s: %(message)s",
    )
    agent = ClientAgent(args.server, args.port)
    agent.start()
    print(f"Agent çalışıyor. Client ID: {agent.client_id}")
    print("Çıkmak için Ctrl+C")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()
