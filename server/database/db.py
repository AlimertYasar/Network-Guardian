"""
Network Guardian - SQLite Veritabanı Katmanı
=============================================
Tüm tablo şemaları ve temel CRUD işlemleri burada.

Tablolar:
    clients          - Kayıtlı client bilgisayarlar
    users            - Client başına kullanıcı oturumları
    whitelist        - İzinli domain listesi (global)
    access_requests  - Engellenen sitelere yapılan erişim talepleri
    visits           - Ziyaret edilen siteler (denetim/raporlama için)
    blocks           - Engellenen istekler
    anomalies        - AI'ın tespit ettiği şüpheli olaylar
"""

from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional


# DB dosyası bu modülün yanında oluşturulur (server klasörü altında)
DEFAULT_DB_PATH = Path(__file__).parent / "guardian.db"


# ---------------------------------------------------------------------------
# Şema (CREATE TABLE IF NOT EXISTS ile idempotent)
# ---------------------------------------------------------------------------
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS clients (
    client_id     TEXT PRIMARY KEY,           -- UUID veya MAC tabanlı
    hostname      TEXT NOT NULL,
    ip_address    TEXT,
    first_seen    REAL NOT NULL,              -- unix epoch
    last_seen     REAL NOT NULL,
    is_online     INTEGER NOT NULL DEFAULT 0, -- 0/1
    is_blocked    INTEGER NOT NULL DEFAULT 0  -- yönetici tamamen kestiyse
);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id     TEXT NOT NULL,
    username      TEXT NOT NULL,
    session_start REAL NOT NULL,
    session_end   REAL,                       -- NULL = hâlâ aktif
    FOREIGN KEY (client_id) REFERENCES clients(client_id)
);

CREATE TABLE IF NOT EXISTS whitelist (
    domain        TEXT PRIMARY KEY,
    added_at      REAL NOT NULL,
    added_by      TEXT,                       -- 'admin' veya 'ai_auto'
    note          TEXT
);

CREATE TABLE IF NOT EXISTS access_requests (
    request_id    TEXT PRIMARY KEY,           -- UUID, client tarafından üretilir
    client_id     TEXT NOT NULL,
    username      TEXT,
    url           TEXT NOT NULL,
    domain        TEXT NOT NULL,
    reason        TEXT,
    requested_at  REAL NOT NULL,
    decided_at    REAL,
    decision      TEXT NOT NULL DEFAULT 'PENDING',  -- PENDING/APPROVED/REJECTED
    ai_verdict    TEXT,                       -- AI'ın önerisi: APPROVE/REJECT
    ai_reason     TEXT,                       -- AI'ın gerekçesi (kısa)
    ai_score      REAL,                       -- 0..1 güven skoru
    admin_note    TEXT,                       -- yönetici notu
    FOREIGN KEY (client_id) REFERENCES clients(client_id)
);

CREATE TABLE IF NOT EXISTS visits (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id     TEXT NOT NULL,
    username      TEXT,
    domain        TEXT NOT NULL,
    url           TEXT,
    visit_time    REAL NOT NULL,
    bytes_xfer    INTEGER DEFAULT 0,
    FOREIGN KEY (client_id) REFERENCES clients(client_id)
);

CREATE TABLE IF NOT EXISTS blocks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id     TEXT NOT NULL,
    username      TEXT,
    domain        TEXT NOT NULL,
    url           TEXT,
    block_time    REAL NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(client_id)
);

CREATE TABLE IF NOT EXISTS anomalies (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id     TEXT,
    username      TEXT,
    detected_at   REAL NOT NULL,
    severity      TEXT NOT NULL,              -- LOW/MEDIUM/HIGH
    category      TEXT NOT NULL,              -- 'unusual_hours','volume_spike','new_domain' vb.
    description   TEXT NOT NULL,
    metadata_json TEXT,                       -- ek detaylar JSON
    acknowledged  INTEGER NOT NULL DEFAULT 0
);

-- Sık sorgulanan kolonlar için index'ler
CREATE INDEX IF NOT EXISTS idx_visits_client_time ON visits(client_id, visit_time);
CREATE INDEX IF NOT EXISTS idx_visits_domain ON visits(domain);
CREATE INDEX IF NOT EXISTS idx_requests_status ON access_requests(decision);
CREATE INDEX IF NOT EXISTS idx_anomalies_ack ON anomalies(acknowledged, detected_at);
"""


# ---------------------------------------------------------------------------
# DB sınıfı - thread-safe SQLite
# ---------------------------------------------------------------------------
class Database:
    """
    SQLite üzerine ince thread-safe katman.

    Not: SQLite tek bir bağlantıyı birden fazla thread'den kullanmak için
    `check_same_thread=False` gerektirir, ama yine de yazma işlemlerini
    seri yapmak için bir RLock kullanıyoruz.
    """

    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            isolation_level=None,   # autocommit; transaction'ları biz yöneteceğiz
        )
        self._conn.row_factory = sqlite3.Row
        # WAL modu = okuma yazmayı bloklamasın
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA_SQL)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Bir blok içindeki yazmaları tek transaction'da yapar."""
        with self._lock:
            try:
                self._conn.execute("BEGIN")
                yield self._conn
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -----------------------------------------------------------------
    # Yüksek seviyeli yardımcılar
    # -----------------------------------------------------------------
    def upsert_client(self, client_id: str, hostname: str, ip: str = "") -> None:
        now = time.time()
        with self.transaction() as c:
            existing = c.execute(
                "SELECT client_id FROM clients WHERE client_id=?", (client_id,)
            ).fetchone()
            if existing:
                c.execute(
                    "UPDATE clients SET hostname=?, ip_address=?, last_seen=?, is_online=1 "
                    "WHERE client_id=?",
                    (hostname, ip, now, client_id),
                )
            else:
                c.execute(
                    "INSERT INTO clients (client_id, hostname, ip_address, first_seen, last_seen, is_online) "
                    "VALUES (?,?,?,?,?,1)",
                    (client_id, hostname, ip, now, now),
                )

    def mark_client_offline(self, client_id: str) -> None:
        self.execute("UPDATE clients SET is_online=0 WHERE client_id=?", (client_id,))

    def touch_client(self, client_id: str) -> None:
        """Heartbeat geldiğinde last_seen'i güncelle."""
        self.execute(
            "UPDATE clients SET last_seen=?, is_online=1 WHERE client_id=?",
            (time.time(), client_id),
        )

    def list_clients(self) -> list[sqlite3.Row]:
        return self.query("SELECT * FROM clients ORDER BY hostname")

    # ---- Whitelist ----
    def add_to_whitelist(self, domain: str, added_by: str = "admin", note: str = "") -> None:
        domain = domain.lower().strip()
        with self.transaction() as c:
            c.execute(
                "INSERT OR IGNORE INTO whitelist (domain, added_at, added_by, note) "
                "VALUES (?,?,?,?)",
                (domain, time.time(), added_by, note),
            )

    def remove_from_whitelist(self, domain: str) -> None:
        self.execute("DELETE FROM whitelist WHERE domain=?", (domain.lower().strip(),))

    def get_whitelist(self) -> list[str]:
        rows = self.query("SELECT domain FROM whitelist ORDER BY domain")
        return [r["domain"] for r in rows]

    def is_whitelisted(self, domain: str) -> bool:
        domain = domain.lower().strip()
        # Tam eşleşme veya alt domain (örn. mail.google.com -> google.com whitelist'teyse)
        parts = domain.split(".")
        candidates = ['.'.join(parts[i:]) for i in range(len(parts) - 1)]
        candidates.append(domain)
        placeholders = ",".join("?" * len(candidates))
        row = self.query_one(
            f"SELECT 1 FROM whitelist WHERE domain IN ({placeholders}) LIMIT 1",
            tuple(candidates),
        )
        return row is not None

    # ---- Erişim talepleri ----
    def insert_access_request(
        self,
        request_id: str,
        client_id: str,
        username: str,
        url: str,
        domain: str,
        reason: str,
    ) -> None:
        self.execute(
            "INSERT INTO access_requests "
            "(request_id, client_id, username, url, domain, reason, requested_at, decision) "
            "VALUES (?,?,?,?,?,?,?, 'PENDING')",
            (request_id, client_id, username, url, domain, reason, time.time()),
        )

    def update_request_ai(
        self, request_id: str, verdict: str, reason: str, score: float
    ) -> None:
        self.execute(
            "UPDATE access_requests SET ai_verdict=?, ai_reason=?, ai_score=? "
            "WHERE request_id=?",
            (verdict, reason, score, request_id),
        )

    def decide_request(self, request_id: str, decision: str, admin_note: str = "") -> None:
        self.execute(
            "UPDATE access_requests SET decision=?, decided_at=?, admin_note=? "
            "WHERE request_id=?",
            (decision, time.time(), admin_note, request_id),
        )

    def get_pending_requests(self) -> list[sqlite3.Row]:
        return self.query(
            "SELECT * FROM access_requests WHERE decision='PENDING' "
            "ORDER BY requested_at DESC"
        )

    def get_request(self, request_id: str) -> Optional[sqlite3.Row]:
        return self.query_one(
            "SELECT * FROM access_requests WHERE request_id=?", (request_id,)
        )

    # ---- Loglar ----
    def log_visit(
        self,
        client_id: str,
        username: str,
        domain: str,
        url: str,
        bytes_xfer: int = 0,
    ) -> None:
        self.execute(
            "INSERT INTO visits (client_id, username, domain, url, visit_time, bytes_xfer) "
            "VALUES (?,?,?,?,?,?)",
            (client_id, username, domain, url, time.time(), bytes_xfer),
        )

    def log_block(self, client_id: str, username: str, domain: str, url: str) -> None:
        self.execute(
            "INSERT INTO blocks (client_id, username, domain, url, block_time) "
            "VALUES (?,?,?,?,?)",
            (client_id, username, domain, url, time.time()),
        )

    # ---- Anomali ----
    def insert_anomaly(
        self,
        client_id: Optional[str],
        username: Optional[str],
        severity: str,
        category: str,
        description: str,
        metadata_json: str = "",
    ) -> int:
        cur = self.execute(
            "INSERT INTO anomalies "
            "(client_id, username, detected_at, severity, category, description, metadata_json) "
            "VALUES (?,?,?,?,?,?,?)",
            (client_id, username, time.time(), severity, category, description, metadata_json),
        )
        return cur.lastrowid

    def get_unack_anomalies(self) -> list[sqlite3.Row]:
        return self.query(
            "SELECT * FROM anomalies WHERE acknowledged=0 ORDER BY detected_at DESC"
        )

    # ---- Raporlama ----
    def get_visits_in_range(
        self, start_ts: float, end_ts: float, client_id: Optional[str] = None
    ) -> list[sqlite3.Row]:
        if client_id:
            return self.query(
                "SELECT * FROM visits WHERE visit_time BETWEEN ? AND ? AND client_id=? "
                "ORDER BY visit_time DESC",
                (start_ts, end_ts, client_id),
            )
        return self.query(
            "SELECT * FROM visits WHERE visit_time BETWEEN ? AND ? "
            "ORDER BY visit_time DESC",
            (start_ts, end_ts),
        )

    def get_top_domains(self, limit: int = 20) -> list[sqlite3.Row]:
        return self.query(
            "SELECT domain, COUNT(*) AS hits, SUM(bytes_xfer) AS bytes "
            "FROM visits GROUP BY domain ORDER BY hits DESC LIMIT ?",
            (limit,),
        )


# Tek bir global instance kullanmak için yardımcı (server tarafı)
_db_instance: Optional[Database] = None


def get_db(db_path: Path = DEFAULT_DB_PATH) -> Database:
    global _db_instance
    if _db_instance is None:
        _db_instance = Database(db_path)
    return _db_instance
