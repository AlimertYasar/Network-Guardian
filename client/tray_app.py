"""
Network Guardian - Client Tray Uygulaması
==========================================
PyQt6 ile sistem tepsisinde çalışır. Kullanıcı sağ tıklayıp:
  - "Erişim İste"   -> Bir URL için yöneticiye talep gönder
  - "Durum"         -> Sunucu bağlantı durumu, whitelist sayısı
  - "Çıkış"         -> Sadece görsel kapatır, agent arka planda çalışmaya devam eder
                      (ileride hizmet/service olarak çalıştırılacak)

Çalıştırma:
    python tray_app.py --server 192.168.1.10
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from urllib.parse import urlparse

# Üst paket import
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QIcon, QAction, QPixmap, QPainter, QColor, QFont
from PyQt6.QtWidgets import (
    QApplication, QSystemTrayIcon, QMenu, QDialog, QVBoxLayout, QHBoxLayout,
    QLineEdit, QTextEdit, QPushButton, QLabel, QMessageBox, QWidget,
)

from client.agent import ClientAgent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Basit programatik ikon (tray için, dış dosya gerekmesin diye)
# ---------------------------------------------------------------------------
def make_shield_icon(color: str = "#74c7ec") -> QIcon:
    pix = QPixmap(64, 64)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QColor(color))
    p.setPen(Qt.PenStyle.NoPen)
    # Kalkan şekli (basit poligon)
    points = [(32, 4), (58, 16), (54, 44), (32, 60), (10, 44), (6, 16)]
    from PyQt6.QtGui import QPolygon
    from PyQt6.QtCore import QPoint
    poly = QPolygon([QPoint(x, y) for x, y in points])
    p.drawPolygon(poly)
    p.setPen(QColor("white"))
    f = QFont("Segoe UI", 28, QFont.Weight.Bold)
    p.setFont(f)
    p.drawText(pix.rect(), Qt.AlignmentFlag.AlignCenter, "G")
    p.end()
    return QIcon(pix)


# ---------------------------------------------------------------------------
# Erişim talebi diyaloğu
# ---------------------------------------------------------------------------
class RequestDialog(QDialog):
    """Kullanıcı engellenen bir siteye erişim talebi gönderir."""

    def __init__(self, agent: ClientAgent, parent=None):
        super().__init__(parent)
        self.agent = agent
        self.setWindowTitle("Site Erişim Talebi")
        self.setMinimumWidth(460)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Erişmek istediğiniz site adresi (URL):"))
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://ornek.com")
        layout.addWidget(self.url_edit)

        layout.addWidget(QLabel("Erişim sebebiniz (yöneticiye iletilecek):"))
        self.reason_edit = QTextEdit()
        self.reason_edit.setPlaceholderText("Örnek: Ders projem için kaynak araştırması")
        self.reason_edit.setFixedHeight(80)
        layout.addWidget(self.reason_edit)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel = QPushButton("İptal")
        cancel.clicked.connect(self.reject)
        send = QPushButton("Talebi Gönder")
        send.setDefault(True)
        send.clicked.connect(self._submit)
        btn_row.addWidget(cancel)
        btn_row.addWidget(send)
        layout.addLayout(btn_row)

    def _submit(self) -> None:
        url = self.url_edit.text().strip()
        if not url:
            QMessageBox.warning(self, "Eksik bilgi", "Lütfen bir URL girin.")
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        if not domain:
            QMessageBox.warning(self, "Geçersiz URL", "Lütfen geçerli bir URL girin.")
            return
        reason = self.reason_edit.toPlainText().strip()
        request_id = self.agent.request_access(url, domain, reason)
        QMessageBox.information(
            self,
            "Talep Gönderildi",
            f"Talebiniz yöneticiye iletildi.\n\nTalep ID: {request_id[:8]}\n"
            f"Onaylandığında siteye erişebileceksiniz.",
        )
        self.accept()


# ---------------------------------------------------------------------------
# Karar bildirimleri için Qt sinyalleri (worker thread -> UI thread köprüsü)
# ---------------------------------------------------------------------------
class AgentSignals(QObject):
    decision_received = pyqtSignal(dict)
    connection_changed = pyqtSignal(bool)


# ---------------------------------------------------------------------------
# Ana tray uygulaması
# ---------------------------------------------------------------------------
class GuardianTray(QSystemTrayIcon):
    def __init__(self, agent: ClientAgent, app: QApplication):
        super().__init__(make_shield_icon("#74c7ec"))
        self.agent = agent
        self.app = app
        self.signals = AgentSignals()

        self.setToolTip("Network Guardian - Bağlanıyor...")
        self._build_menu()

        # Agent callback'lerini Qt sinyallerine bağla (thread-safe geçiş)
        self.agent.on_decision = self.signals.decision_received.emit
        self.agent.on_connected = lambda: self.signals.connection_changed.emit(True)
        self.agent.on_disconnected = lambda: self.signals.connection_changed.emit(False)

        self.signals.decision_received.connect(self._on_decision)
        self.signals.connection_changed.connect(self._on_connection_changed)

        self.activated.connect(self._on_activated)

    def _build_menu(self) -> None:
        menu = QMenu()
        self.status_action = QAction("Bağlanıyor...")
        self.status_action.setEnabled(False)
        menu.addAction(self.status_action)
        menu.addSeparator()

        request_action = QAction("Erişim İste...")
        request_action.triggered.connect(self._open_request_dialog)
        menu.addAction(request_action)

        info_action = QAction("Durum / Whitelist")
        info_action.triggered.connect(self._show_status)
        menu.addAction(info_action)

        menu.addSeparator()
        quit_action = QAction("Tray'i Kapat")
        quit_action.triggered.connect(self.app.quit)
        menu.addAction(quit_action)

        self.setContextMenu(menu)

    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger:  # tek tık
            self._open_request_dialog()

    def _open_request_dialog(self) -> None:
        dlg = RequestDialog(self.agent)
        dlg.exec()

    def _show_status(self) -> None:
        wl = self.agent.whitelist.all()
        text = (
            f"Sunucu: {self.agent.server_host}:{self.agent.server_port}\n"
            f"Client ID: {self.agent.client_id[:8]}...\n"
            f"Kullanıcı: {self.agent.username}\n"
            f"Hostname: {self.agent.hostname}\n\n"
            f"Whitelist'te {len(wl)} domain var:\n"
            + "\n".join(f"  • {d}" for d in wl[:30])
        )
        if len(wl) > 30:
            text += f"\n  ... ve {len(wl) - 30} tane daha"
        QMessageBox.information(None, "Network Guardian Durumu", text)

    # -----------------------------------------------------------------
    # Sinyal slotları
    # -----------------------------------------------------------------
    def _on_decision(self, data: dict) -> None:
        decision = data.get("decision", "?")
        request_id = data.get("request_id", "")
        note = data.get("note", "")
        if decision == "APPROVED":
            self.showMessage(
                "✅ Talep Onaylandı",
                f"Talep #{request_id[:8]} onaylandı."
                + (f"\nNot: {note}" if note else ""),
                QSystemTrayIcon.MessageIcon.Information,
                5000,
            )
        else:
            self.showMessage(
                "❌ Talep Reddedildi",
                f"Talep #{request_id[:8]} reddedildi."
                + (f"\nNot: {note}" if note else ""),
                QSystemTrayIcon.MessageIcon.Warning,
                5000,
            )

    def _on_connection_changed(self, connected: bool) -> None:
        if connected:
            self.setIcon(make_shield_icon("#a6e3a1"))  # yeşil
            self.setToolTip("Network Guardian - Bağlı")
            self.status_action.setText("● Sunucuya bağlı")
        else:
            self.setIcon(make_shield_icon("#f38ba8"))  # kırmızı
            self.setToolTip("Network Guardian - Bağlantı yok")
            self.status_action.setText("● Bağlantı kesildi")


# ---------------------------------------------------------------------------
# Giriş noktası
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="127.0.0.1", help="Yönetici sunucu IP")
    parser.add_argument("--port", type=int, default=9009)
    parser.add_argument("--proxy-bridge-port", type=int, default=9010)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(threadName)s] %(levelname)s %(name)s: %(message)s",
    )

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)  # Pencere kapanınca uygulama kapanmasın

    if not QSystemTrayIcon.isSystemTrayAvailable():
        QMessageBox.critical(None, "Hata", "Sistem tepsisi desteklenmiyor.")
        return 1

    agent = ClientAgent(args.server, args.port)
    agent.start()
    agent.start_proxy_bridge(args.proxy_bridge_port)

    tray = GuardianTray(agent, app)
    tray.show()

    rc = app.exec()
    agent.stop()
    return rc


if __name__ == "__main__":
    sys.exit(main())
