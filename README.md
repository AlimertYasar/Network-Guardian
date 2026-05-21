# Network Guardian

Çok bilgisayarlı ortamlar (iş yeri, internet kafe, okul) için merkezi yönetilen, yapay zeka destekli firewall / içerik filtreleme sistemi.

## Mimari

```
┌─────────────────────────────────────────────────────────────┐
│                    YÖNETİCİ BİLGİSAYAR                      │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  PyQt6 Yönetici Paneli (admin_app.py)                │  │
│  │  - Canlı izleme   - Talep onaylama   - Raporlar      │  │
│  └─────────────────┬────────────────────────────────────┘  │
│                    │                                        │
│  ┌─────────────────▼────────────────────────────────────┐  │
│  │  TCP Komuta Sunucusu (port 9009)                     │  │
│  │  - Client kayıt    - Komut gönderme    - Veri alma   │  │
│  └─────────────────┬────────────────────────────────────┘  │
│                    │                                        │
│  ┌─────────┬───────┴───────┬─────────────┐                 │
│  ▼         ▼               ▼             ▼                 │
│ SQLite   AI Modülü    Whitelist Mgr  Anomaly Det.          │
│         (Ollama)                                            │
└────────────────────┬────────────────────────────────────────┘
                     │ TCP/JSON (port 9009)
        ┌────────────┼────────────┐
        ▼            ▼            ▼
┌──────────────┐ ┌──────────┐ ┌──────────┐
│ CLIENT PC 1  │ │ CLIENT 2 │ │ CLIENT N │
│              │ │          │ │          │
│ ┌──────────┐ │ │   ...    │ │   ...    │
│ │ Tray UI  │ │ │          │ │          │
│ ├──────────┤ │ │          │ │          │
│ │ Proxy    │◄┼─┼──────────┼─┼──────────┤  Tüm trafik
│ │ (mitm)   │ │ │          │ │          │  proxy'den geçer
│ ├──────────┤ │ │          │ │          │
│ │ Agent    │ │ │          │ │          │
│ │(socket)  │ │ │          │ │          │
│ └──────────┘ │ │          │ │          │
└──────────────┘ └──────────┘ └──────────┘
```

## Klasör Yapısı

```
network_guardian/
├── server/                  # Yönetici bilgisayarda çalışacak
│   ├── admin_app.py        # PyQt6 ana arayüz
│   ├── command_server.py   # TCP socket sunucu
│   ├── ui/                 # PyQt6 widget'ları (dashboard, talepler, raporlar)
│   ├── ai/                 # Ollama entegrasyonu + anomali tespiti
│   ├── database/           # SQLite şema ve sorgular
│   └── network/            # Whitelist yöneticisi, protokol
├── client/                  # Her client bilgisayarda çalışacak
│   ├── agent.py            # Ana ajan: proxy + sunucuyla iletişim
│   ├── proxy_engine.py     # mitmproxy tabanlı filtreleme
│   ├── tray_app.py         # Sistem tepsisi UI (talep gönderme)
│   ├── ui/                 # Talep penceresi
│   └── network/            # Sunucuya bağlanan socket istemcisi
├── shared/                  # Hem client hem server kullanır
│   ├── protocol.py         # Mesaj formatları, komutlar
│   └── crypto.py           # TLS / token yardımcıları
└── docs/                    # Mimari dokümanlar, kurulum
```

## Teknoloji Yığını

| Bileşen          | Teknoloji                              |
|------------------|----------------------------------------|
| Dil              | Python 3.11+                           |
| GUI              | PyQt6                                  |
| Veritabanı       | SQLite                                 |
| Trafik Yakalama  | mitmproxy (HTTP/HTTPS proxy)           |
| Soket            | Python stdlib `socket` + `threading`   |
| AI (LLM)         | Ollama + llama3.2:3b                   |
| AI (Anomali)     | scikit-learn IsolationForest           |
| Platform         | Windows 10/11                          |

## Çalışma Akışı

### 1. Engelleme
Client'ta tüm HTTP/HTTPS trafiği yerel proxy'ye yönlendirilir. Proxy her istekte hostname'i whitelist ile karşılaştırır:
- ✅ Whitelist'te varsa → geçir
- ❌ Yoksa → engelle + kullanıcıya "talep gönder" sayfası göster

### 2. Talep Süreci
Kullanıcı tray'den veya engelleme sayfasından "Bu siteye erişim izni iste" tıklar.
1. Client → Sunucuya talep gönderir (`{cmd: REQUEST_ACCESS, url, reason, user}`)
2. Sunucudaki AI talebi değerlendirir (Ollama'ya prompt: "Bu site iş ortamına uygun mu?")
3. AI'ın notu + talep, yöneticinin paneline düşer
4. Yönetici onayla/reddet → karar client'a iletilir, whitelist güncellenir

### 3. İzleme & Anomali
Her client her N saniyede bir özet gönderir: ziyaret edilen domainler, byte miktarı, süre.
- Veriler SQLite'a yazılır
- IsolationForest periyodik olarak çalışıp anormallikleri işaretler (örn. gece 3'te 2 saat youtube, normalin 10 katı veri vb.)
- Anomali bulunursa yöneticinin paneline uyarı düşer

## Kazanımlar

- **Soket programlama:** Custom TCP protokolü tasarımı, multi-client sunucu, JSON mesajlaşma
- **Ağ güvenliği:** HTTPS interception, sertifika yönetimi, whitelist mantığı
- **AI entegrasyonu:** LLM ile kural tabanlı karar verme + ML ile davranış analizi
