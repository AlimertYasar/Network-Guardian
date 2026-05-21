"""
Network Guardian - AI İçerik Değerlendirici
============================================
Ollama'da çalışan bir LLM (varsayılan: llama3.2:3b) kullanarak
erişim taleplerini değerlendirir.

Akış:
    1. Yönetici paneline bir REQUEST_ACCESS düşer
    2. Bu modül AI'a sorar: "Bu site iş ortamına uygun mu?"
    3. AI {verdict, reason, score} döner
    4. Yönetici son kararı verir (AI sadece tavsiye eder)

Ollama kurulumu:
    https://ollama.com indir, kur.
    Ardından:  ollama pull llama3.2:3b

İletişim Ollama'nın yerel HTTP API'si üzerinden:
    POST http://localhost:11434/api/generate
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Optional
from urllib import request as urlreq
from urllib.error import URLError

logger = logging.getLogger(__name__)

OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "llama3.2:3b"
REQUEST_TIMEOUT = 30  # saniye


# AI'a verilen prompt - yapılandırılmış JSON çıktı bekliyoruz
SYSTEM_PROMPT = """Sen bir kurumsal ağ güvenlik asistanısın. Görev: Bir kullanıcının
erişmek istediği bir web sitesinin iş ortamı / okul / internet kafe gibi
genel kullanım amaçlı bir ağda izin verilmesi uygun olup olmadığını değerlendirmek.

Kriterler:
- Yetişkin/pornografik içerik           -> REJECT
- Kumar / bahis siteleri                 -> REJECT
- Bilinen zararlı yazılım / phishing     -> REJECT
- Yasa dışı içerik (warez, piratlık)     -> REJECT
- Sosyal medya (durum belirsizse)        -> REVIEW (insanın karar vermesi için)
- Eğitim, dokümantasyon, haberler        -> APPROVE
- Yazılım geliştirme, GitHub vb.         -> APPROVE
- Resmi kurumlar, e-devlet               -> APPROVE
- Tanımadığın site                        -> REVIEW (düşük güven)

Yanıtını SADECE şu JSON formatında ver, başka hiçbir şey yazma:
{"verdict": "APPROVE" | "REJECT" | "REVIEW", "reason": "kısa Türkçe açıklama", "score": 0.0-1.0}
"score" güven seviyendir (1.0 = çok eminim).
"""


@dataclass
class AIVerdict:
    """AI'ın bir talep için verdiği karar."""
    verdict: str   # APPROVE / REJECT / REVIEW
    reason: str
    score: float   # 0..1

    @property
    def suggests_approval(self) -> bool:
        return self.verdict == "APPROVE" and self.score >= 0.6

    @property
    def suggests_rejection(self) -> bool:
        return self.verdict == "REJECT" and self.score >= 0.6


class OllamaEvaluator:
    """Ollama HTTP API'sini kullanarak site değerlendirir."""

    def __init__(self, model: str = DEFAULT_MODEL, url: str = OLLAMA_URL):
        self.model = model
        self.url = url

    def is_available(self) -> bool:
        """Ollama sunucusu çalışıyor mu? Başlangıçta kontrol için."""
        try:
            req = urlreq.Request(self.url.replace("/api/generate", "/api/tags"))
            with urlreq.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except (URLError, OSError):
            return False

    def evaluate(self, url: str, domain: str, user_reason: str = "") -> AIVerdict:
        """
        Bir URL'yi değerlendir. Ollama yoksa veya hata olursa REVIEW döner
        (yani insan karar versin, sistem güvenli tarafta kalır).
        """
        prompt = self._build_prompt(url, domain, user_reason)
        try:
            raw = self._call_ollama(prompt)
            return self._parse_response(raw)
        except Exception as e:
            logger.warning("AI değerlendirme başarısız: %s", e)
            return AIVerdict(
                verdict="REVIEW",
                reason=f"AI servisine ulaşılamadı: {e}",
                score=0.0,
            )

    def _build_prompt(self, url: str, domain: str, user_reason: str) -> str:
        reason_part = f'Kullanıcının verdiği gerekçe: "{user_reason}"' if user_reason else ""
        return (
            f"{SYSTEM_PROMPT}\n\n"
            f"Değerlendirilecek istek:\n"
            f"  Domain: {domain}\n"
            f"  Tam URL: {url}\n"
            f"  {reason_part}\n\n"
            f"JSON yanıt:"
        )

    def _call_ollama(self, prompt: str) -> str:
        body = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            # daha deterministik cevaplar için sıcaklığı düşürelim
            "options": {"temperature": 0.2, "num_predict": 200},
        }).encode("utf-8")
        req = urlreq.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlreq.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return payload.get("response", "")

    def _parse_response(self, raw: str) -> AIVerdict:
        """LLM çıktısından JSON'u sökmeye çalış."""
        # LLM bazen markdown kod bloğuna sarar; ilk { ile son } arasını alalım
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if not match:
            return AIVerdict("REVIEW", f"AI çıktısı çözümlenemedi: {raw[:80]}", 0.0)
        try:
            obj = json.loads(match.group(0))
            verdict = str(obj.get("verdict", "REVIEW")).upper()
            if verdict not in ("APPROVE", "REJECT", "REVIEW"):
                verdict = "REVIEW"
            reason = str(obj.get("reason", ""))[:300]
            score = float(obj.get("score", 0.5))
            score = max(0.0, min(1.0, score))
            return AIVerdict(verdict, reason, score)
        except (json.JSONDecodeError, ValueError, TypeError) as e:
            return AIVerdict("REVIEW", f"AI yanıtı geçersiz: {e}", 0.0)


# Modül seviyesi singleton (admin app başlatırken bir kere oluştur)
_evaluator: Optional[OllamaEvaluator] = None


def get_evaluator(model: str = DEFAULT_MODEL) -> OllamaEvaluator:
    global _evaluator
    if _evaluator is None:
        _evaluator = OllamaEvaluator(model=model)
    return _evaluator
