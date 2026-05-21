# Network Guardian — Kurulum ve Kullanım Kılavuzu

## 1. Ön Gereksinimler

- **Python 3.11 veya üstü** (https://python.org)
- **Windows 10/11** (hedef platform)
- **Ollama** (yönetici bilgisayarda) — https://ollama.com
- En az **2 bilgisayar** test için (1 yönetici + 1 client) ya da aynı bilgisayarda iki süreç

---

## 2. Yönetici Bilgisayarı Kurulumu

### 2.1. Bağımlılıkları yükle

```bash
cd network_guardian
python -m pip install -r requirements.txt
```

### 2.2. Ollama'yı kur ve modeli indir

```bash
# Ollama'yı indir & kur (https://ollama.com)
# Sonra terminalden:
ollama pull llama3.2:3b
ollama serve         # arka planda çalışır, normalde otomatik başlar
```

Test etmek için:
```bash
curl http://localhost:11434/api/tags
```

### 2.3. Yönetici panelini başlat

```bash
cd network_guardian
python -m server.admin_app
```

İlk çalıştırmada `server/database/guardian.db` dosyası otomatik oluşturulur.

Sunucu varsayılan olarak **0.0.0.0:9009** üzerinde dinler. Windows Defender Firewall sorabilir → "izin ver".

### 2.4. Yönetici bilgisayarın IP adresini öğren

```bash
ipconfig | findstr IPv4
```

Bu IP'yi (örn. `192.168.1.10`) client'lara vereceksiniz.

---

## 3. Client Bilgisayar(lar) Kurulumu

Her bir client bilgisayarda yapılacaklar:

### 3.1. Bağımlılıkları yükle

```bash
cd network_guardian
python -m pip install -r requirements.txt
```

### 3.2. mitmproxy sertifikasını kur (HTTPS için ŞART)

mitmproxy'yi bir kez çalıştır → CA sertifikasını üretsin:
```bash
mitmdump --listen-port 8080
# Birkaç saniye bekle, sonra Ctrl+C
```

Sertifikayı Windows güvenilir köklere ekle (yönetici PowerShell):
```powershell
certutil -addstore -f "ROOT" "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.cer"
```

> ⚠️ Bu adım atlanırsa HTTPS siteleri "sertifika hatası" verir. Bu sertifika eklenince mitmproxy HTTPS trafiğini de görüp filtreleyebilir.

### 3.3. Sistem proxy'sini etkinleştir

```bash
python -m client.configure_proxy enable
```

Bu komut Windows kayıt defterine `127.0.0.1:8080`'i proxy olarak yazar.

Geri almak için: `python -m client.configure_proxy disable`

### 3.4. Üç bileşeni başlat (3 ayrı terminal)

**Terminal 1 — mitmproxy filtreleme motoru:**
```bash
mitmdump -s client/proxy_engine.py -p 8080
```

**Terminal 2 — agent (sunucuyla konuşan ana ajan):**
```bash
python -m client.agent --server 192.168.1.10 --port 9009
```

**Terminal 3 — tray UI (kullanıcı arayüzü):**
```bash
python -m client.tray_app --server 192.168.1.10
```

> İleride hepsini tek bir Windows servisi olarak paketleyebilirsin (NSSM veya pyinstaller + sc.exe ile). Şimdilik geliştirme aşamasında 3 terminal yeterli.

---

## 4. İlk Test

1. Yönetici panelinde **Whitelist** sekmesinden `wikipedia.org` ekle.
2. Client bilgisayarda tarayıcıdan `https://wikipedia.org` aç → **çalışır**.
3. Aynı tarayıcıdan `https://reddit.com` aç → **engelleme sayfası** görürsün.
4. Tray simgesine tıkla → "Erişim İste" → URL'yi yapıştır → gönder.
5. Yönetici panelinde **Talepler** sekmesinde talep belirir, AI'ın önerisi 1-3 sn içinde gelir.
6. **Onayla** → client'ın whitelist'i otomatik güncellenir → reddit artık açılır.

---

## 5. Klasör ve Dosya Konumları

| Yer | İçerik |
|---|---|
| `server/database/guardian.db` | Tüm SQLite verisi (yönetici PC'de) |
| `~/.network_guardian/whitelist.json` | Client'taki yerel whitelist (proxy okur) |
| `~/.network_guardian/client_id` | Kalıcı client UUID'si |
| `~/.mitmproxy/` | mitmproxy CA sertifikası |

---

## 6. Sık Karşılaşılan Sorunlar

**"Ollama bulunamadı" uyarısı:** Ollama servisinin çalıştığından emin ol (`ollama serve`). AI olmasa da sistem çalışır, sadece talepler "Değerlendiriliyor..." kalır ve insan kararına bırakılır.

**HTTPS siteler açılmıyor:** mitmproxy sertifikası eklenmemiş. `certutil` komutunu yeniden çalıştır.

**Client sunucuya bağlanamıyor:** Yönetici PC'de port 9009 firewall'da açık mı? `netstat -an | findstr 9009` ile kontrol et.

**Tray simgesi görünmüyor:** Windows Ayarlar → Görev Çubuğu → Görünmesi gereken simgeler bölümünden "Network Guardian"ı aç.

**`ImportError: PyQt6`:** Sanal ortam kullanıyorsan aktif değil olabilir. `pip install PyQt6`'yi tekrar çalıştır.

---

## 7. Güvenlik Notları (Bilmen iyi)

- Bu sistem **eğitim amaçlı** bir prototip. Gerçek kurumsal ortamda ek olarak şunlar gerekir:
  - Client-server arası **TLS** (şu an düz TCP — `shared/crypto.py` planlandı ama henüz yok)
  - Client kimlik doğrulama (token/cert)
  - Agent ve proxy'nin kullanıcı tarafından kapatılamaması (Windows servis + UAC ayarları)
  - mitmproxy sertifikasının özel bir kurum CA'sı altında imzalanması
- **mitmproxy ile HTTPS interception** kullanıcının trafiğini açar — bu bir özellik (içerik denetlemek için) ama aynı zamanda risk. Yasal/etik düzlemde kullanıcılar bilgilendirilmeli.

---

## 8. Geliştirme Yol Haritası

Bitince yapılabilecekler (ileride):
- [ ] `shared/crypto.py` ile TLS sarması ekle
- [ ] Client agent'ı Windows servisi yap (`pywin32` veya `nssm`)
- [ ] Tray UI ile proxy/agent'ı tek process içinde toplama
- [ ] Web tabanlı yönetici paneli (PyQt6 yanı sıra)
- [ ] Saatlik/günlük rapor PDF/Excel export
- [ ] Ollama yerine alternatif modeller (kategori bazlı önceden eğitilmiş bir BERT/distilbert)
- [ ] Whitelist'e regex/wildcard pattern desteği
- [ ] Kullanıcı bazlı whitelist (sadece bu kullanıcı bu siteye girebilsin)
