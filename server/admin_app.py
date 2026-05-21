"""
Network Guardian - Yönetici Paneli
====================================
PyQt6 tabanlı admin uygulaması. Sekmeler:
  1. Dashboard       - Özet, aktif client'lar, son aktiviteler
  2. Talepler        - Bekleyen erişim talepleri (AI önerisiyle birlikte)
  3. Whitelist       - Domain ekleme/çıkarma
  4. Loglar          - Ziyaret/engelleme arama ve filtreleme
  5. Anomaliler      - AI'ın tespit ettiği şüpheli olaylar
  6. Client'lar      - Bağlı bilgisayarların listesi, internetten kesme

Çalıştırma:
    python admin_app.py
"""

from __future__ import annotations

import logging
import sys
import time
from datetime import datetime
from pathlib import Path

# Üst paket
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QAction, QColor, QIcon
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QPushButton, QLabel, QLineEdit, QTextEdit,
    QHeaderView, QMessageBox, QSplitter, QGroupBox, QFormLayout, QComboBox,
    QSpinBox, QDateTimeEdit, QStatusBar, QInputDialog, QMenu,
)

from server.command_server import CommandServer
from server.database import get_db
from server.ai import get_evaluator, AnomalyOrchestrator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Thread-safe Qt sinyalleri (server callback'leri için)
# ---------------------------------------------------------------------------
class ServerSignals(QObject):
    client_connected = pyqtSignal(str, str)         # client_id, hostname
    client_disconnected = pyqtSignal(str)
    access_request = pyqtSignal(dict)               # AI değerlendirilmiş talep
    log_event = pyqtSignal(str, str, dict)          # client_id, type, data


# ---------------------------------------------------------------------------
# Yardımcı: epoch -> okunabilir tarih
# ---------------------------------------------------------------------------
def fmt_time(ts: float | None) -> str:
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Dashboard sekmesi
# ---------------------------------------------------------------------------
class DashboardTab(QWidget):
    def __init__(self, server: CommandServer):
        super().__init__()
        self.server = server
        self.db = server.db

        layout = QVBoxLayout(self)

        # Üstte istatistik kutucukları
        stats_row = QHBoxLayout()
        self.lbl_clients = self._make_stat_card("Bağlı Client", "0")
        self.lbl_pending = self._make_stat_card("Bekleyen Talep", "0")
        self.lbl_whitelist = self._make_stat_card("Whitelist Boyutu", "0")
        self.lbl_anomalies = self._make_stat_card("Açık Anomali", "0")
        for w in (self.lbl_clients, self.lbl_pending, self.lbl_whitelist, self.lbl_anomalies):
            stats_row.addWidget(w)
        layout.addLayout(stats_row)

        # Son aktiviteler tablosu
        layout.addWidget(QLabel("<h3>Son Aktiviteler</h3>"))
        self.activity_table = QTableWidget(0, 4)
        self.activity_table.setHorizontalHeaderLabels(["Zaman", "Tür", "Client", "Detay"])
        self.activity_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.activity_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.activity_table)

        # 5 saniyede bir yenile
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(5000)
        self.refresh()

    def _make_stat_card(self, title: str, value: str) -> QGroupBox:
        box = QGroupBox(title)
        v = QVBoxLayout(box)
        lbl = QLabel(value)
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet("font-size: 32px; font-weight: bold; color: #74c7ec;")
        v.addWidget(lbl)
        box.value_label = lbl  # type: ignore[attr-defined]
        return box

    def refresh(self) -> None:
        self.lbl_clients.value_label.setText(str(len(self.server.list_connected())))  # type: ignore
        pending = self.db.get_pending_requests()
        self.lbl_pending.value_label.setText(str(len(pending)))  # type: ignore
        self.lbl_whitelist.value_label.setText(str(len(self.db.get_whitelist())))  # type: ignore
        anomalies = self.db.get_unack_anomalies()
        self.lbl_anomalies.value_label.setText(str(len(anomalies)))  # type: ignore

    def append_activity(self, kind: str, client_id: str, detail: str) -> None:
        row = 0
        self.activity_table.insertRow(row)
        self.activity_table.setItem(row, 0, QTableWidgetItem(fmt_time(time.time())))
        self.activity_table.setItem(row, 1, QTableWidgetItem(kind))
        self.activity_table.setItem(row, 2, QTableWidgetItem(client_id[:8]))
        self.activity_table.setItem(row, 3, QTableWidgetItem(detail))
        # En fazla 100 satır tut
        while self.activity_table.rowCount() > 100:
            self.activity_table.removeRow(self.activity_table.rowCount() - 1)


# ---------------------------------------------------------------------------
# Talepler sekmesi - en kritik UI
# ---------------------------------------------------------------------------
class RequestsTab(QWidget):
    def __init__(self, server: CommandServer):
        super().__init__()
        self.server = server
        self.db = server.db

        layout = QVBoxLayout(self)

        header = QHBoxLayout()
        header.addWidget(QLabel("<h3>Bekleyen Erişim Talepleri</h3>"))
        header.addStretch()
        refresh_btn = QPushButton("Yenile")
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn)
        layout.addLayout(header)

        # Tablo + detay paneli yan yana
        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Zaman", "Kullanıcı", "Domain", "AI Önerisi", "Skor", "ID"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.itemSelectionChanged.connect(self._on_select)
        splitter.addWidget(self.table)

        # Detay paneli
        detail_box = QGroupBox("Talep Detayı")
        d_layout = QVBoxLayout(detail_box)
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        d_layout.addWidget(self.detail_text)

        d_layout.addWidget(QLabel("Yönetici Notu (opsiyonel):"))
        self.note_edit = QLineEdit()
        d_layout.addWidget(self.note_edit)

        btn_row = QHBoxLayout()
        self.approve_btn = QPushButton("✓ Onayla")
        self.approve_btn.setStyleSheet("background-color: #a6e3a1; color: #1e1e2e; padding: 8px;")
        self.approve_btn.clicked.connect(self._approve)
        self.reject_btn = QPushButton("✗ Reddet")
        self.reject_btn.setStyleSheet("background-color: #f38ba8; color: #1e1e2e; padding: 8px;")
        self.reject_btn.clicked.connect(self._reject)
        btn_row.addWidget(self.approve_btn)
        btn_row.addWidget(self.reject_btn)
        d_layout.addLayout(btn_row)

        splitter.addWidget(detail_box)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter)

        # 3 saniyede bir yenile
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(3000)
        self.refresh()

    def refresh(self) -> None:
        rows = self.db.get_pending_requests()
        # Mevcut seçimi koru (varsa)
        selected_id = self._selected_request_id()

        self.table.setRowCount(0)
        for r in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(fmt_time(r["requested_at"])))
            self.table.setItem(row, 1, QTableWidgetItem(r["username"] or "?"))
            self.table.setItem(row, 2, QTableWidgetItem(r["domain"]))

            verdict = r["ai_verdict"] or "Değerlendiriliyor..."
            verdict_item = QTableWidgetItem(verdict)
            if verdict == "APPROVE":
                verdict_item.setBackground(QColor("#a6e3a1"))
                verdict_item.setForeground(QColor("#1e1e2e"))
            elif verdict == "REJECT":
                verdict_item.setBackground(QColor("#f38ba8"))
                verdict_item.setForeground(QColor("#1e1e2e"))
            elif verdict == "REVIEW":
                verdict_item.setBackground(QColor("#f9e2af"))
                verdict_item.setForeground(QColor("#1e1e2e"))
            self.table.setItem(row, 3, verdict_item)

            score = r["ai_score"]
            self.table.setItem(row, 4, QTableWidgetItem(f"{score:.2f}" if score is not None else "-"))
            self.table.setItem(row, 5, QTableWidgetItem(r["request_id"]))

            if r["request_id"] == selected_id:
                self.table.selectRow(row)

    def _selected_request_id(self) -> str:
        row = self.table.currentRow()
        if row < 0 or row >= self.table.rowCount():
            return ""
        item = self.table.item(row, 5)
        return item.text() if item else ""

    def _on_select(self) -> None:
        rid = self._selected_request_id()
        if not rid:
            self.detail_text.clear()
            return
        r = self.db.get_request(rid)
        if not r:
            return
        text = (
            f"<b>Talep ID:</b> {r['request_id']}<br>"
            f"<b>Zaman:</b> {fmt_time(r['requested_at'])}<br>"
            f"<b>Kullanıcı:</b> {r['username']} (client: {r['client_id'][:8]})<br>"
            f"<b>Domain:</b> {r['domain']}<br>"
            f"<b>Tam URL:</b> {r['url']}<br><br>"
            f"<b>Kullanıcının gerekçesi:</b><br>{r['reason'] or '<i>(belirtilmemiş)</i>'}<br><br>"
            f"<b>━━━ AI Değerlendirmesi ━━━</b><br>"
            f"<b>Önerisi:</b> {r['ai_verdict'] or 'henüz alınmadı'}<br>"
            f"<b>Güven Skoru:</b> {f'{r['ai_score']:.2f}' if r['ai_score'] is not None else '-'}<br>"
            f"<b>Gerekçe:</b><br>{r['ai_reason'] or '-'}"
        )
        self.detail_text.setHtml(text)

    def _approve(self) -> None:
        rid = self._selected_request_id()
        if not rid:
            return
        note = self.note_edit.text().strip()
        ok = self.server.approve_request(rid, note)
        if ok:
            self.note_edit.clear()
            self.refresh()
        else:
            QMessageBox.warning(self, "Hata", "Talep bulunamadı veya onaylanamadı.")

    def _reject(self) -> None:
        rid = self._selected_request_id()
        if not rid:
            return
        note = self.note_edit.text().strip()
        ok = self.server.reject_request(rid, note)
        if ok:
            self.note_edit.clear()
            self.refresh()
        else:
            QMessageBox.warning(self, "Hata", "Talep bulunamadı veya reddedilemedi.")


# ---------------------------------------------------------------------------
# Whitelist sekmesi
# ---------------------------------------------------------------------------
class WhitelistTab(QWidget):
    def __init__(self, server: CommandServer):
        super().__init__()
        self.server = server
        self.db = server.db

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<h3>İzinli Domain Listesi</h3>"))

        add_row = QHBoxLayout()
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("ornek.com (alt domain'leri otomatik kapsar)")
        self.domain_input.returnPressed.connect(self._add)
        add_btn = QPushButton("Ekle")
        add_btn.clicked.connect(self._add)
        add_row.addWidget(self.domain_input)
        add_row.addWidget(add_btn)
        layout.addLayout(add_row)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Domain", "Eklenme", "Ekleyen", "Not"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_ctx_menu)
        layout.addWidget(self.table)

        info = QLabel(
            "<i>Sağ tık ile silebilirsiniz. Bir domain eklediğinizde tüm "
            "alt domain'leri (örn: mail.x.com için x.com) otomatik kapsanır.</i>"
        )
        info.setStyleSheet("color: #a6adc8;")
        layout.addWidget(info)

        self.refresh()

    def refresh(self) -> None:
        rows = self.db.query("SELECT * FROM whitelist ORDER BY added_at DESC")
        self.table.setRowCount(0)
        for r in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(r["domain"]))
            self.table.setItem(row, 1, QTableWidgetItem(fmt_time(r["added_at"])))
            self.table.setItem(row, 2, QTableWidgetItem(r["added_by"] or "-"))
            self.table.setItem(row, 3, QTableWidgetItem(r["note"] or ""))

    def _add(self) -> None:
        domain = self.domain_input.text().strip().lower()
        if not domain:
            return
        # http:// vs varsa temizle
        if "://" in domain:
            from urllib.parse import urlparse
            domain = urlparse(domain).hostname or domain
        self.server.add_whitelist_domain(domain, note="manuel ekleme")
        self.domain_input.clear()
        self.refresh()

    def _show_ctx_menu(self, pos) -> None:
        row = self.table.indexAt(pos).row()
        if row < 0:
            return
        domain = self.table.item(row, 0).text()
        menu = QMenu(self)
        act = menu.addAction(f"'{domain}' silinsin")
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen == act:
            self.server.remove_whitelist_domain(domain)
            self.refresh()


# ---------------------------------------------------------------------------
# Loglar sekmesi
# ---------------------------------------------------------------------------
class LogsTab(QWidget):
    def __init__(self, server: CommandServer):
        super().__init__()
        self.db = server.db

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<h3>Aktivite Logları</h3>"))

        # Filtre satırı
        f = QHBoxLayout()
        self.kind_combo = QComboBox()
        self.kind_combo.addItems(["Ziyaretler", "Engellemeler"])
        self.kind_combo.currentIndexChanged.connect(self.refresh)
        f.addWidget(QLabel("Tür:"))
        f.addWidget(self.kind_combo)

        f.addWidget(QLabel("Son"))
        self.hours_spin = QSpinBox()
        self.hours_spin.setRange(1, 168)
        self.hours_spin.setValue(24)
        self.hours_spin.valueChanged.connect(self.refresh)
        f.addWidget(self.hours_spin)
        f.addWidget(QLabel("saat"))

        f.addWidget(QLabel("Domain içerir:"))
        self.domain_filter = QLineEdit()
        self.domain_filter.textChanged.connect(self.refresh)
        f.addWidget(self.domain_filter)

        f.addStretch()
        refresh_btn = QPushButton("Yenile")
        refresh_btn.clicked.connect(self.refresh)
        f.addWidget(refresh_btn)
        layout.addLayout(f)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Zaman", "Client", "Kullanıcı", "Domain", "URL"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)

        self.refresh()

    def refresh(self) -> None:
        kind = self.kind_combo.currentText()
        hours = self.hours_spin.value()
        domain_q = self.domain_filter.text().strip().lower()

        since = time.time() - hours * 3600
        if kind == "Ziyaretler":
            sql = "SELECT * FROM visits WHERE visit_time >= ?"
            params: list = [since]
            if domain_q:
                sql += " AND lower(domain) LIKE ?"
                params.append(f"%{domain_q}%")
            sql += " ORDER BY visit_time DESC LIMIT 500"
            rows = self.db.query(sql, tuple(params))
            time_col = "visit_time"
        else:
            sql = "SELECT * FROM blocks WHERE block_time >= ?"
            params = [since]
            if domain_q:
                sql += " AND lower(domain) LIKE ?"
                params.append(f"%{domain_q}%")
            sql += " ORDER BY block_time DESC LIMIT 500"
            rows = self.db.query(sql, tuple(params))
            time_col = "block_time"

        self.table.setRowCount(0)
        for r in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(fmt_time(r[time_col])))
            self.table.setItem(row, 1, QTableWidgetItem((r["client_id"] or "")[:8]))
            self.table.setItem(row, 2, QTableWidgetItem(r["username"] or "-"))
            self.table.setItem(row, 3, QTableWidgetItem(r["domain"]))
            self.table.setItem(row, 4, QTableWidgetItem(r["url"] or ""))


# ---------------------------------------------------------------------------
# Anomali sekmesi
# ---------------------------------------------------------------------------
class AnomaliesTab(QWidget):
    def __init__(self, server: CommandServer):
        super().__init__()
        self.db = server.db
        self.orchestrator = AnomalyOrchestrator(self.db)

        layout = QVBoxLayout(self)

        header = QHBoxLayout()
        header.addWidget(QLabel("<h3>Tespit Edilen Anomaliler</h3>"))
        header.addStretch()
        scan_btn = QPushButton("Şimdi Tara")
        scan_btn.clicked.connect(self._scan_now)
        header.addWidget(scan_btn)
        train_btn = QPushButton("ML Modelini Eğit")
        train_btn.clicked.connect(self._train)
        header.addWidget(train_btn)
        layout.addLayout(header)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Zaman", "Önem", "Kategori", "Client", "Kullanıcı", "Açıklama"]
        )
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_ctx_menu)
        layout.addWidget(self.table)

        # Otomatik 60 saniyede bir tara
        self.scan_timer = QTimer(self)
        self.scan_timer.timeout.connect(self._scan_silent)
        self.scan_timer.start(60_000)

        self.refresh()

    def refresh(self) -> None:
        rows = self.db.get_unack_anomalies()
        self.table.setRowCount(0)
        for r in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(fmt_time(r["detected_at"])))

            sev_item = QTableWidgetItem(r["severity"])
            color = {"HIGH": "#f38ba8", "MEDIUM": "#f9e2af", "LOW": "#a6e3a1"}.get(
                r["severity"], "#cdd6f4"
            )
            sev_item.setBackground(QColor(color))
            sev_item.setForeground(QColor("#1e1e2e"))
            self.table.setItem(row, 1, sev_item)

            self.table.setItem(row, 2, QTableWidgetItem(r["category"]))
            self.table.setItem(row, 3, QTableWidgetItem((r["client_id"] or "-")[:8]))
            self.table.setItem(row, 4, QTableWidgetItem(r["username"] or "-"))

            desc_item = QTableWidgetItem(r["description"])
            desc_item.setData(Qt.ItemDataRole.UserRole, r["id"])
            self.table.setItem(row, 5, desc_item)

    def _scan_now(self) -> None:
        findings = self.orchestrator.run_cycle(train_ml=False)
        self.refresh()
        QMessageBox.information(
            self, "Tarama Tamamlandı",
            f"{len(findings)} yeni anomali tespit edildi."
        )

    def _scan_silent(self) -> None:
        try:
            self.orchestrator.run_cycle(train_ml=False)
            self.refresh()
        except Exception:
            logger.exception("Otomatik anomali taraması başarısız")

    def _train(self) -> None:
        if not self.orchestrator.ml:
            QMessageBox.warning(
                self, "ML Mevcut Değil",
                "scikit-learn yüklü değil. `pip install scikit-learn` ile kurun."
            )
            return
        n = self.orchestrator.ml.train()
        QMessageBox.information(
            self, "Eğitim Tamamlandı",
            f"ML modeli {n} örnekle eğitildi." if n
            else "Eğitim için yeterli geçmiş veri yok (en az 20 saatlik veri gerekli)."
        )

    def _show_ctx_menu(self, pos) -> None:
        row = self.table.indexAt(pos).row()
        if row < 0:
            return
        item = self.table.item(row, 5)
        anomaly_id = item.data(Qt.ItemDataRole.UserRole)
        menu = QMenu(self)
        ack = menu.addAction("Onayla / Kapat")
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen == ack:
            self.db.execute("UPDATE anomalies SET acknowledged=1 WHERE id=?", (anomaly_id,))
            self.refresh()


# ---------------------------------------------------------------------------
# Client'lar sekmesi
# ---------------------------------------------------------------------------
class ClientsTab(QWidget):
    def __init__(self, server: CommandServer):
        super().__init__()
        self.server = server
        self.db = server.db

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<h3>Kayıtlı Client'lar</h3>"))

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Hostname", "IP", "Client ID", "İlk Görülme", "Son Görülme", "Durum"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_ctx_menu)
        layout.addWidget(self.table)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(5000)
        self.refresh()

    def refresh(self) -> None:
        rows = self.db.list_clients()
        self.table.setRowCount(0)
        for r in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(r["hostname"]))
            self.table.setItem(row, 1, QTableWidgetItem(r["ip_address"] or "-"))
            self.table.setItem(row, 2, QTableWidgetItem(r["client_id"]))
            self.table.setItem(row, 3, QTableWidgetItem(fmt_time(r["first_seen"])))
            self.table.setItem(row, 4, QTableWidgetItem(fmt_time(r["last_seen"])))

            online = bool(r["is_online"])
            status_item = QTableWidgetItem("● Online" if online else "○ Offline")
            status_item.setForeground(QColor("#a6e3a1" if online else "#6c7086"))
            self.table.setItem(row, 5, status_item)

    def _show_ctx_menu(self, pos) -> None:
        row = self.table.indexAt(pos).row()
        if row < 0:
            return
        client_id = self.table.item(row, 2).text()
        menu = QMenu(self)
        disconnect_act = menu.addAction("İnternet Erişimini Kes")
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen == disconnect_act:
            ok = self.server.force_disconnect_client(client_id)
            QMessageBox.information(
                self,
                "Sonuç",
                "Client'a kesim komutu gönderildi." if ok
                else "Client şu an bağlı değil."
            )


# ---------------------------------------------------------------------------
# Ana pencere
# ---------------------------------------------------------------------------
class AdminMainWindow(QMainWindow):
    def __init__(self, server: CommandServer):
        super().__init__()
        self.server = server
        self.signals = ServerSignals()

        self.setWindowTitle("Network Guardian - Yönetici Paneli")
        self.resize(1200, 760)
        self._apply_theme()

        # Sekmeler
        tabs = QTabWidget()
        self.dashboard = DashboardTab(server)
        self.requests = RequestsTab(server)
        self.whitelist = WhitelistTab(server)
        self.logs = LogsTab(server)
        self.anomalies = AnomaliesTab(server)
        self.clients = ClientsTab(server)

        tabs.addTab(self.dashboard, "📊 Dashboard")
        tabs.addTab(self.requests, "📨 Talepler")
        tabs.addTab(self.whitelist, "✅ Whitelist")
        tabs.addTab(self.logs, "📋 Loglar")
        tabs.addTab(self.anomalies, "⚠️ Anomaliler")
        tabs.addTab(self.clients, "💻 Client'lar")
        self.setCentralWidget(tabs)

        # Status bar
        self.setStatusBar(QStatusBar())
        self._update_statusbar()

        # Server callback'lerini sinyallere bağla (thread-safe)
        server.on_client_connected = lambda c: self.signals.client_connected.emit(
            c.client_id, c.hostname
        )
        server.on_client_disconnected = self.signals.client_disconnected.emit
        server.on_access_request = self.signals.access_request.emit
        server.on_log_event = lambda cid, t, d: self.signals.log_event.emit(cid, t, d)

        self.signals.client_connected.connect(self._on_client_conn)
        self.signals.client_disconnected.connect(self._on_client_disc)
        self.signals.access_request.connect(self._on_access_request)
        self.signals.log_event.connect(self._on_log_event)

        # AI servisi var mı kontrol et
        QTimer.singleShot(500, self._check_ai)

    def _apply_theme(self) -> None:
        # Catppuccin Mocha esinli koyu tema
        self.setStyleSheet("""
            QMainWindow, QWidget { background-color: #1e1e2e; color: #cdd6f4; }
            QTabWidget::pane { border: 1px solid #313244; background: #181825; }
            QTabBar::tab {
                background: #313244; color: #cdd6f4; padding: 8px 18px;
                border-top-left-radius: 6px; border-top-right-radius: 6px;
            }
            QTabBar::tab:selected { background: #585b70; color: #f5e0dc; }
            QTableWidget {
                background: #181825; alternate-background-color: #1e1e2e;
                gridline-color: #313244; selection-background-color: #45475a;
            }
            QHeaderView::section {
                background: #313244; color: #cdd6f4; padding: 6px;
                border: 1px solid #1e1e2e;
            }
            QPushButton {
                background: #45475a; color: #cdd6f4; padding: 6px 12px;
                border: 1px solid #585b70; border-radius: 4px;
            }
            QPushButton:hover { background: #585b70; }
            QLineEdit, QTextEdit, QComboBox, QSpinBox {
                background: #313244; color: #cdd6f4; padding: 5px;
                border: 1px solid #45475a; border-radius: 4px;
            }
            QGroupBox {
                border: 1px solid #45475a; border-radius: 6px; margin-top: 12px;
                padding-top: 8px; font-weight: bold;
            }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
            QStatusBar { background: #181825; }
        """)

    def _update_statusbar(self) -> None:
        connected = len(self.server.list_connected())
        self.statusBar().showMessage(
            f"Sunucu çalışıyor (port {self.server.port})  •  "
            f"{connected} client bağlı"
        )

    # ---- Sinyal slotları ----
    def _on_client_conn(self, client_id: str, hostname: str) -> None:
        self.dashboard.append_activity("CONNECT", client_id, f"{hostname} bağlandı")
        self._update_statusbar()
        self.dashboard.refresh()
        self.clients.refresh()

    def _on_client_disc(self, client_id: str) -> None:
        self.dashboard.append_activity("DISCONNECT", client_id, "bağlantı kesildi")
        self._update_statusbar()
        self.dashboard.refresh()
        self.clients.refresh()

    def _on_access_request(self, row: dict) -> None:
        self.dashboard.append_activity(
            "REQUEST",
            row.get("client_id", ""),
            f"{row.get('domain', '')} - AI: {row.get('ai_verdict', '?')}"
        )
        self.dashboard.refresh()
        self.requests.refresh()

    def _on_log_event(self, client_id: str, event_type: str, data: dict) -> None:
        # Çok sık geleceği için sadece engelleme'yi feed'e koy
        if event_type == "block":
            self.dashboard.append_activity(
                "BLOCK", client_id, f"{data.get('domain', '')} engellendi"
            )

    def _check_ai(self) -> None:
        ev = get_evaluator()
        if not ev.is_available():
            QMessageBox.warning(
                self,
                "Ollama Bulunamadı",
                "Ollama servisi (http://localhost:11434) çalışmıyor.\n\n"
                "AI tabanlı talep değerlendirmesi devre dışı kalacak.\n"
                "Kurulum: https://ollama.com\n"
                "Model: ollama pull llama3.2:3b"
            )

    def closeEvent(self, ev) -> None:
        self.server.stop()
        super().closeEvent(ev)


# ---------------------------------------------------------------------------
# Giriş noktası
# ---------------------------------------------------------------------------
def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(threadName)s] %(levelname)s %(name)s: %(message)s",
    )

    app = QApplication(sys.argv)

    # DB ve sunucu
    db = get_db()
    evaluator = get_evaluator()
    server = CommandServer(db=db, evaluator=evaluator)
    server.start()

    win = AdminMainWindow(server)
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
