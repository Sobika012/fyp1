from __future__ import annotations

import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import urlparse


@dataclass
class SimpleHttpResponse:
    status: int
    headers: Dict[str, str]
    body_text: str


class SimpleHttpClient:
    def __init__(self, timeout: int = 5, retries: int = 1):
        self.timeout = timeout
        self.retries = retries

    # ✅ helper: make sure scheme exists
    @staticmethod
    def _normalize_url(url: str) -> str:
        if not url:
            return ""
        u = url.strip()
        p = urlparse(u)
        if not p.scheme:
            u = "http://" + u
        return u

    def get(self, url: str) -> Optional[SimpleHttpResponse]:
        url = self._normalize_url(url)
        if not url:
            return None

        for attempt in range(self.retries + 1):
            try:
                req = urllib.request.Request(
                    url=url,
                    headers={"User-Agent": "AVDVP-Validator/1.0"},
                    method="GET",
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    headers = {k.lower(): v for k, v in dict(r.headers).items()}
                    body = r.read().decode("utf-8", errors="ignore")
                    return SimpleHttpResponse(status=r.status, headers=headers, body_text=body)
            except Exception:
                if attempt < self.retries:
                    time.sleep(0.4 * (attempt + 1))
                else:
                    return None

    # ✅ NEW: POST
    def post(
        self,
        url: str,
        data: str,
        content_type: str = "application/x-www-form-urlencoded",
    ) -> Optional[SimpleHttpResponse]:
        url = self._normalize_url(url)
        if not url:
            return None

        payload = (data or "").encode("utf-8")

        for attempt in range(self.retries + 1):
            try:
                req = urllib.request.Request(
                    url=url,
                    data=payload,
                    headers={
                        "User-Agent": "AVDVP-Validator/1.0",
                        "Content-Type": content_type,
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    headers = {k.lower(): v for k, v in dict(r.headers).items()}
                    body = r.read().decode("utf-8", errors="ignore")
                    return SimpleHttpResponse(status=r.status, headers=headers, body_text=body)
            except Exception:
                if attempt < self.retries:
                    time.sleep(0.4 * (attempt + 1))
                else:
                    return None

