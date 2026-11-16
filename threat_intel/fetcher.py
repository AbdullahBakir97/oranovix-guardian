"""
HTTP access of the Threat Feed.

``HttpFetcher`` is the only class that opens a connection. It is handed
to the sources, so tests replace it with a fake and never touch the
network. A request carries the URL, a fixed User-Agent and the cache
validators of the last download, and nothing else.
"""
from __future__ import annotations

import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, Optional
from urllib.parse import urlsplit


class FetchError(RuntimeError):
    """The request was refused, failed, or the answer was not acceptable."""


@dataclass(frozen=True)
class FetchResponse:
    status: int
    body: bytes = b""
    etag: str = ""
    last_modified: str = ""
    elapsed_ms: int = 0

    @property
    def unchanged(self) -> bool:
        """The server answered 304: the copy we already have is current."""
        return self.status == 304

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


class Fetcher(ABC):
    """Downloads one URL."""

    @abstractmethod
    def get(self, url: str, etag: str = "", last_modified: str = "") -> FetchResponse:
        """GET *url*. Any HTTP status is returned; ``FetchError`` means no usable answer."""


class _CheckedRedirects(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only when the new address passes the same checks."""

    def __init__(self, check: Callable[[str], None]) -> None:
        self._check = check

    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Any:
        self._check(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


Opener = Callable[[urllib.request.Request, float], Any]


class HttpFetcher(Fetcher):
    """GET over https with a size cap, a timeout and conditional requests."""

    USER_AGENT = "OranovixGuardian"
    TIMEOUT_SECONDS = 10.0
    MAX_BYTES = 5 * 1024 * 1024

    def __init__(
        self,
        allow_http: bool = False,
        max_bytes: int = MAX_BYTES,
        truncate: bool = False,
        timeout: float = TIMEOUT_SECONDS,
        opener: Optional[Opener] = None,
    ) -> None:
        """*allow_http* and *truncate* exist for uptime checks of the user's own sites.

        With *truncate* a long answer is cut at *max_bytes* instead of refused.
        """
        self._schemes = frozenset({"https", "http"} if allow_http else {"https"})
        self._max_bytes = max_bytes
        self._truncate = truncate
        self._timeout = timeout
        self._open = opener or self._default_opener()

    def _default_opener(self) -> Opener:
        director = urllib.request.build_opener(_CheckedRedirects(self._check_url))
        return lambda request, timeout: director.open(request, timeout=timeout)

    def get(self, url: str, etag: str = "", last_modified: str = "") -> FetchResponse:
        self._check_url(url)
        headers = {"User-Agent": self.USER_AGENT, "Accept": "*/*"}
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified
        request = urllib.request.Request(url, headers=headers, method="GET")

        started = time.monotonic()
        try:
            with self._open(request, self._timeout) as response:
                body = self._read(response)
                status = int(getattr(response, "status", 200) or 200)
                response_headers = response.headers
        except urllib.error.HTTPError as exc:
            # 304 and error pages arrive as exceptions; the status is the answer.
            status, body, response_headers = exc.code, b"", exc.headers
        except FetchError:
            raise
        except Exception as exc:
            raise FetchError(f"{type(exc).__name__}: {self._reason(exc)}") from exc

        return FetchResponse(
            status=status,
            body=body,
            etag=self._header(response_headers, "ETag"),
            last_modified=self._header(response_headers, "Last-Modified"),
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )

    def _check_url(self, url: str) -> None:
        try:
            parts = urlsplit(url)
            host = parts.hostname
        except ValueError as exc:
            raise FetchError("The address is not valid.") from exc
        if parts.scheme.lower() not in self._schemes or not host:
            allowed = " or ".join(sorted(self._schemes))
            raise FetchError(f"Only {allowed} addresses are allowed.")

    def _read(self, response: Any) -> bytes:
        declared = self._header(response.headers, "Content-Length")
        if not self._truncate and declared.isdigit() and int(declared) > self._max_bytes:
            raise FetchError(f"The answer is larger than {self._max_bytes} bytes.")
        body = response.read(self._max_bytes + 1)
        if len(body) > self._max_bytes:
            if not self._truncate:
                raise FetchError(f"The answer is larger than {self._max_bytes} bytes.")
            body = body[: self._max_bytes]
        return body

    @staticmethod
    def _header(headers: Any, name: str) -> str:
        if headers is None:
            return ""
        return str(headers.get(name) or "").strip()[:300]

    @staticmethod
    def _reason(exc: Exception) -> str:
        return str(getattr(exc, "reason", "") or exc)[:200]
