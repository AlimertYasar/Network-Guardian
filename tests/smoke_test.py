"""
Network Guardian - Hızlı Sağlık Testi
=======================================
Hiçbir GUI veya gerçek ağ bağlantısı kurmadan, modüllerin temel çalışmasını
doğrular. Geliştirme sırasında "her şey hâlâ çalışıyor mu?" demek için.

Çalıştırma:
    python -m tests.smoke_test
"""

from __future__ import annotations

import socket
import tempfile
import threading
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared.protocol import (
    Message, Command, Decision,
    send_message, recv_message,
    make_register, make_request_access, make_whitelist_update,
)
from server.database import Database


def ok(msg: str) -> None:
    print(f"  ✓ {msg}")


def fail(msg: str) -> None:
    print(f"  ✗ {msg}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# 1) Protokol round-trip testi
# ---------------------------------------------------------------------------
def test_protocol() -> None:
    print("\n[1] Protokol serileştirme testi...")
    msg = make_register("uuid-123", "TEST-PC", "ali")
    raw = msg.to_json_bytes()
    rebuilt = Message.from_json_bytes(raw)
    assert rebuilt.cmd == Command.REGISTER.value
    assert rebuilt.client_id == "uuid-123"
    assert rebuilt.data["hostname"] == "TEST-PC"
    ok("JSON serileştirme/çözme çalışıyor")

    # Length-prefixed framing testi (loopback üzerinden)
    sa, sb = socket.socketpair()
    try:
        send_message(sa, msg)
        received = recv_message(sb)
        assert received.cmd == msg.cmd
        assert received.client_id == msg.client_id
        ok("Length-prefixed framing çalışıyor")
    finally:
        sa.close()
        sb.close()


# ---------------------------------------------------------------------------
# 2) Veritabanı testi
# ---------------------------------------------------------------------------
def test_database() -> None:
    print("\n[2] Veritabanı testi...")
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "test.db"
        db = Database(db_path)

        # Client kaydı
        db.upsert_client("c1", "PC-1", "10.0.0.5")
        clients = db.list_clients()
        assert len(clients) == 1
        assert clients[0]["hostname"] == "PC-1"
        ok("Client upsert çalışıyor")

        # Whitelist
        db.add_to_whitelist("wikipedia.org")
        db.add_to_whitelist("github.com", added_by="ai_auto")
        wl = db.get_whitelist()
        assert "wikipedia.org" in wl
        assert "github.com" in wl
        ok("Whitelist ekleme çalışıyor")

        # Subdomain matching
        assert db.is_whitelisted("en.wikipedia.org"), "alt domain eşleşmedi"
        assert db.is_whitelisted("wikipedia.org")
        assert not db.is_whitelisted("reddit.com")
        ok("Subdomain whitelist eşleşmesi çalışıyor")

        # Erişim talebi
        db.insert_access_request("req1", "c1", "ali", "https://x.com/", "x.com", "test")
        db.update_request_ai("req1", "REVIEW", "Sosyal medya, insan karar versin", 0.7)
        pending = db.get_pending_requests()
        assert len(pending) == 1
        assert pending[0]["ai_verdict"] == "REVIEW"
        ok("Erişim talebi DB'ye yazıldı, AI değerlendirmesi güncellendi")

        # Karar verme
        db.decide_request("req1", Decision.APPROVED.value, "OK ders için")
        r = db.get_request("req1")
        assert r["decision"] == "APPROVED"
        assert r["admin_note"] == "OK ders için"
        ok("Karar verme akışı çalışıyor")

        # Loglar
        db.log_visit("c1", "ali", "wikipedia.org", "https://wikipedia.org/", 1024)
        db.log_block("c1", "ali", "reddit.com", "https://reddit.com/")
        visits = db.query("SELECT COUNT(*) AS n FROM visits")
        blocks = db.query("SELECT COUNT(*) AS n FROM blocks")
        assert visits[0]["n"] == 1 and blocks[0]["n"] == 1
        ok("Visit ve block logları yazıldı")

        # Anomali
        db.insert_anomaly("c1", "ali", "MEDIUM", "test_cat", "Test anomali", "{}")
        anomalies = db.get_unack_anomalies()
        assert len(anomalies) == 1
        ok("Anomali kaydı eklendi")

        db.close()


# ---------------------------------------------------------------------------
# 3) Mini end-to-end socket testi (gerçek server, mock client)
# ---------------------------------------------------------------------------
def test_command_server_loop() -> None:
    print("\n[3] Komut sunucusu mini E2E...")

    from server.command_server import CommandServer
    from server.ai.evaluator import OllamaEvaluator, AIVerdict

    # Stub evaluator - Ollama olmadan da test yapabilelim
    class StubEvaluator(OllamaEvaluator):
        def is_available(self):
            return True
        def evaluate(self, url, domain, user_reason=""):
            return AIVerdict("REVIEW", "stub yanıtı", 0.5)

    with tempfile.TemporaryDirectory() as tmp:
        db = Database(Path(tmp) / "e2e.db")
        server = CommandServer(host="127.0.0.1", port=0, db=db, evaluator=StubEvaluator())
        # port=0 verince OS boş port atar - öğrenelim:
        # CommandServer'ın bind sonrası port'u dinamik olabilir,
        # bu yüzden socket'i biz hazırlayıp port öğrenelim:
        # Basitlik için sabit port deneyelim (test ortamında çakışmaz)
        server.port = 19009
        server.start()
        try:
            time.sleep(0.3)
            # Mock client bağlanır
            with socket.create_connection(("127.0.0.1", 19009), timeout=3) as s:
                send_message(s, make_register("test-cid", "TEST", "tester"))
                # ACK + WHITELIST_UPDATE bekleriz
                ack = recv_message(s)
                assert ack.cmd == Command.ACK.value
                wl = recv_message(s)
                assert wl.cmd == Command.WHITELIST_UPDATE.value
                ok("Client REGISTER ve ilk whitelist senkronu çalıştı")

                # Bir erişim talebi gönder
                send_message(s, make_request_access("test-cid", "https://test.com", "test.com", "test sebebi"))
                ack2 = recv_message(s)
                assert ack2.cmd == Command.ACK.value
                ok("Erişim talebi sunucuda işlendi")

            # AI background thread için biraz bekle
            time.sleep(0.5)
            pending = db.get_pending_requests()
            assert len(pending) == 1, f"beklenen 1 PENDING, bulunan {len(pending)}"
            assert pending[0]["ai_verdict"] == "REVIEW"
            ok("Stub AI değerlendirmesi DB'ye yazıldı")
        finally:
            server.stop()
            db.close()


# ---------------------------------------------------------------------------
# 4) Anomali detektörü kural testi
# ---------------------------------------------------------------------------
def test_anomaly_rules() -> None:
    print("\n[4] Anomali (kural tabanlı) testi...")
    from server.ai.anomaly import RuleBasedDetector

    with tempfile.TemporaryDirectory() as tmp:
        db = Database(Path(tmp) / "anom.db")
        db.upsert_client("c1", "PC-1")

        # 60 tane block kaydı oluştur (eşik 50 -> tetiklenmeli)
        now = time.time()
        for i in range(60):
            db.execute(
                "INSERT INTO blocks (client_id, username, domain, url, block_time) VALUES (?,?,?,?,?)",
                ("c1", "ali", f"site{i}.com", "", now - 60),
            )

        detector = RuleBasedDetector(db)
        findings = detector.run_all(lookback_hours=1)
        block_findings = [f for f in findings if f.category == "excessive_blocks"]
        assert len(block_findings) >= 1, "aşırı engelleme tespiti çalışmadı"
        ok(f"Aşırı engelleme tespiti çalıştı: {block_findings[0].description}")
        db.close()


# ---------------------------------------------------------------------------
# Ana akış
# ---------------------------------------------------------------------------
def main() -> int:
    print("=" * 60)
    print("Network Guardian - Hızlı Sağlık Testi")
    print("=" * 60)

    test_protocol()
    test_database()
    test_command_server_loop()
    test_anomaly_rules()

    print("\n" + "=" * 60)
    print("✅ Tüm testler geçti!")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
