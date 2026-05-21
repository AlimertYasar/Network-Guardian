"""
Network Guardian - Anomali Tespiti
====================================
İki katmanlı yaklaşım:

1) Kural tabanlı (her zaman çalışır, sklearn şart değil):
   - Olağandışı saatte yoğun trafik (örn. 02:00-06:00 arası)
   - Aşırı engelleme (kullanıcı saatte 100+ engellenmiş istek -> bypass deniyor olabilir)
   - Ani veri patlaması (saat ortalamasının 5 katı)

2) ML tabanlı (scikit-learn IsolationForest):
   - Her kullanıcı için (saat, ziyaret_sayısı, byte, farklı_domain_sayısı) feature vektörü
   - Geçmiş saatlik özetler üzerinde eğitilir
   - Yeni saatlik özet skor 'anomali' ise işaretlenir

scikit-learn yoksa modül yine çalışır, sadece ML kısmı devre dışı kalır.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# scikit-learn opsiyonel - yoksa kural tabanlı çalışmaya devam edelim
try:
    import numpy as np  # type: ignore
    from sklearn.ensemble import IsolationForest  # type: ignore
    SKLEARN_AVAILABLE = True
except ImportError:  # pragma: no cover
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn bulunamadı, sadece kural tabanlı anomali tespiti çalışacak")


# Kural eşikleri - prod'da config'e taşınabilir
NIGHT_HOURS = (0, 6)               # 00:00 - 06:00
NIGHT_VISIT_THRESHOLD = 30         # gece saatinde 30+ ziyaret -> şüpheli
BLOCK_RATE_THRESHOLD = 50          # bir saatte 50+ engelleme -> bypass denemesi şüphesi
VOLUME_SPIKE_MULTIPLIER = 5.0      # ortalamanın 5 katı veri -> patlama


@dataclass
class AnomalyFinding:
    """Tespit edilen tek bir anomali."""
    client_id: Optional[str]
    username: Optional[str]
    severity: str                  # LOW / MEDIUM / HIGH
    category: str
    description: str
    metadata: dict


# ---------------------------------------------------------------------------
# Kural tabanlı detektörler
# ---------------------------------------------------------------------------
class RuleBasedDetector:
    """Basit eşik kontrolleri. Veritabanına direkt sorgu atar."""

    def __init__(self, db):
        self.db = db

    def run_all(self, lookback_hours: int = 1) -> list[AnomalyFinding]:
        """Son N saatlik veriyi kontrol et."""
        findings: list[AnomalyFinding] = []
        now = time.time()
        start = now - lookback_hours * 3600

        findings.extend(self._check_night_activity(start, now))
        findings.extend(self._check_excessive_blocks(start, now))
        findings.extend(self._check_volume_spike(start, now))

        return findings

    def _check_night_activity(self, start: float, end: float) -> list[AnomalyFinding]:
        """Gece saatlerinde olağandışı yoğun ziyaret."""
        # SQLite'ta saat hesabı: visit_time'ı datetime'a çevirip strftime
        rows = self.db.query(
            """
            SELECT client_id, username, COUNT(*) AS cnt
            FROM visits
            WHERE visit_time BETWEEN ? AND ?
              AND CAST(strftime('%H', visit_time, 'unixepoch', 'localtime') AS INTEGER)
                  BETWEEN ? AND ?
            GROUP BY client_id, username
            HAVING cnt >= ?
            """,
            (start, end, NIGHT_HOURS[0], NIGHT_HOURS[1] - 1, NIGHT_VISIT_THRESHOLD),
        )
        out = []
        for r in rows:
            out.append(AnomalyFinding(
                client_id=r["client_id"],
                username=r["username"],
                severity="MEDIUM",
                category="unusual_hours",
                description=(
                    f"Kullanıcı {r['username']} gece saatlerinde {r['cnt']} ziyaret yaptı "
                    f"(eşik: {NIGHT_VISIT_THRESHOLD})"
                ),
                metadata={"visit_count": r["cnt"], "window_hours": NIGHT_HOURS},
            ))
        return out

    def _check_excessive_blocks(self, start: float, end: float) -> list[AnomalyFinding]:
        """Çok fazla engelleme = whitelist'i bypass etmeye çalışıyor olabilir."""
        rows = self.db.query(
            """
            SELECT client_id, username, COUNT(*) AS cnt
            FROM blocks
            WHERE block_time BETWEEN ? AND ?
            GROUP BY client_id, username
            HAVING cnt >= ?
            """,
            (start, end, BLOCK_RATE_THRESHOLD),
        )
        out = []
        for r in rows:
            severity = "HIGH" if r["cnt"] > BLOCK_RATE_THRESHOLD * 2 else "MEDIUM"
            out.append(AnomalyFinding(
                client_id=r["client_id"],
                username=r["username"],
                severity=severity,
                category="excessive_blocks",
                description=(
                    f"Kullanıcı {r['username']} 1 saatte {r['cnt']} kez engellendi - "
                    f"yasaklı sitelere erişmeye çalışıyor olabilir"
                ),
                metadata={"block_count": r["cnt"]},
            ))
        return out

    def _check_volume_spike(self, start: float, end: float) -> list[AnomalyFinding]:
        """Bir client'ın trafiği geçmiş ortalamasının çok üzerindeyse uyar."""
        # Son 1 saatlik byte miktarı
        recent = self.db.query(
            "SELECT client_id, SUM(bytes_xfer) AS total "
            "FROM visits WHERE visit_time BETWEEN ? AND ? GROUP BY client_id",
            (start, end),
        )
        # Son 7 günün saatlik ortalaması (kabaca)
        week_ago = end - 7 * 24 * 3600
        baseline = {
            r["client_id"]: r["avg_total"]
            for r in self.db.query(
                """
                SELECT client_id, AVG(hourly_total) AS avg_total FROM (
                    SELECT client_id,
                           strftime('%Y-%m-%d %H', visit_time, 'unixepoch') AS hr,
                           SUM(bytes_xfer) AS hourly_total
                    FROM visits
                    WHERE visit_time BETWEEN ? AND ?
                    GROUP BY client_id, hr
                )
                GROUP BY client_id
                """,
                (week_ago, start),
            )
        }

        out = []
        for r in recent:
            cid = r["client_id"]
            current = r["total"] or 0
            avg = baseline.get(cid, 0)
            if avg > 0 and current > avg * VOLUME_SPIKE_MULTIPLIER and current > 50_000_000:
                # 50MB altındaysa zaten önemsiz - false positive olur
                out.append(AnomalyFinding(
                    client_id=cid,
                    username=None,
                    severity="MEDIUM",
                    category="volume_spike",
                    description=(
                        f"Client {cid} son 1 saatte {_human_bytes(current)} kullandı, "
                        f"ortalaması {_human_bytes(avg)}"
                    ),
                    metadata={"current_bytes": current, "avg_bytes": avg},
                ))
        return out


# ---------------------------------------------------------------------------
# ML tabanlı detektör (opsiyonel)
# ---------------------------------------------------------------------------
class MLDetector:
    """
    IsolationForest ile saatlik kullanım vektörlerini skorla.
    Feature: [saat_of_day, ziyaret_sayısı, toplam_byte, farklı_domain_sayısı]
    """

    def __init__(self, db, contamination: float = 0.05):
        if not SKLEARN_AVAILABLE:
            raise RuntimeError("scikit-learn yüklü değil")
        self.db = db
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
        )
        self._trained = False

    def _build_hourly_features(self, since_ts: float) -> tuple:
        """Saatlik agregat feature matrisi üretir."""
        rows = self.db.query(
            """
            SELECT
                client_id,
                username,
                strftime('%Y-%m-%d %H', visit_time, 'unixepoch', 'localtime') AS hr,
                CAST(strftime('%H', visit_time, 'unixepoch', 'localtime') AS INTEGER) AS hour_of_day,
                COUNT(*) AS visit_cnt,
                SUM(bytes_xfer) AS total_bytes,
                COUNT(DISTINCT domain) AS uniq_domains
            FROM visits
            WHERE visit_time >= ?
            GROUP BY client_id, username, hr
            """,
            (since_ts,),
        )
        features = []
        meta = []
        for r in rows:
            features.append([
                r["hour_of_day"],
                r["visit_cnt"],
                (r["total_bytes"] or 0) / 1_000_000,  # MB
                r["uniq_domains"],
            ])
            meta.append((r["client_id"], r["username"], r["hr"]))
        return np.array(features) if features else np.empty((0, 4)), meta

    def train(self, days_back: int = 14) -> int:
        """Geçmiş veriyle modeli eğit. Eğitilen örnek sayısını döner."""
        since = time.time() - days_back * 24 * 3600
        X, _ = self._build_hourly_features(since)
        if len(X) < 20:
            logger.info("Eğitim için yeterli veri yok (%d örnek)", len(X))
            return 0
        self.model.fit(X)
        self._trained = True
        logger.info("ML anomali modeli %d örnekle eğitildi", len(X))
        return len(X)

    def detect(self, hours_back: int = 1) -> list[AnomalyFinding]:
        if not self._trained:
            return []
        since = time.time() - hours_back * 3600
        X, meta = self._build_hourly_features(since)
        if len(X) == 0:
            return []
        # IsolationForest: -1 = anomali, 1 = normal
        preds = self.model.predict(X)
        scores = self.model.decision_function(X)  # negatife yakın = daha şüpheli
        out = []
        for (cid, user, hr), pred, score, feat in zip(meta, preds, scores, X):
            if pred == -1:
                out.append(AnomalyFinding(
                    client_id=cid,
                    username=user,
                    severity="LOW" if score > -0.1 else "MEDIUM",
                    category="ml_outlier",
                    description=(
                        f"ML modeli {user}@{cid} için olağandışı kullanım deseni tespit etti "
                        f"({hr}: {int(feat[1])} ziyaret, {feat[2]:.1f}MB, "
                        f"{int(feat[3])} farklı domain)"
                    ),
                    metadata={
                        "hour_bucket": hr,
                        "score": float(score),
                        "features": feat.tolist(),
                    },
                ))
        return out


# ---------------------------------------------------------------------------
# Üst seviye orkestratör
# ---------------------------------------------------------------------------
class AnomalyOrchestrator:
    """Tüm detektörleri çalıştırıp DB'ye yazar."""

    def __init__(self, db):
        self.db = db
        self.rule = RuleBasedDetector(db)
        self.ml = MLDetector(db) if SKLEARN_AVAILABLE else None

    def run_cycle(self, train_ml: bool = False) -> list[AnomalyFinding]:
        if train_ml and self.ml:
            try:
                self.ml.train()
            except Exception as e:
                logger.warning("ML eğitimi başarısız: %s", e)

        findings = self.rule.run_all()
        if self.ml:
            try:
                findings.extend(self.ml.detect())
            except Exception as e:
                logger.warning("ML tespit başarısız: %s", e)

        # DB'ye yaz
        for f in findings:
            self.db.insert_anomaly(
                client_id=f.client_id,
                username=f.username,
                severity=f.severity,
                category=f.category,
                description=f.description,
                metadata_json=json.dumps(f.metadata, ensure_ascii=False),
            )
        return findings


# ---------------------------------------------------------------------------
# Yardımcı
# ---------------------------------------------------------------------------
def _human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}PB"
