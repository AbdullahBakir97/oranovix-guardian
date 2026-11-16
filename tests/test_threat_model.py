"""Threat Feed data model and the HTTP fetcher (with a fake opener, no network)."""
from __future__ import annotations

import io
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from email.message import Message
from typing import Any, Dict, List, Optional

import pytest

from feed_fakes import FakeFetcher
from scanner_engine.base import Severity
from threat_intel.fetcher import FetchError, Fetcher, FetchResponse, HttpFetcher
from threat_intel.models import FeedItem, FeedSource, PackageRef, Relevance, SourceHealth
from threat_intel.sanitize import SafeUrl, TextCleaner


# ---------------------------------------------------------------------------
# FeedItem
# ---------------------------------------------------------------------------

def test_id_depends_on_source_and_key_only() -> None:
    first = FeedItem.build("News", "guid-1", "Title", "https://example.org/a")
    again = FeedItem.build("News", "guid-1", "Another title", "https://example.org/b")
    other_source = FeedItem.build("Other", "guid-1", "Title", "https://example.org/a")

    assert first is not None and again is not None and other_source is not None
    assert first.id == again.id
    assert first.id != other_source.id
    assert len(first.id) == 32


def test_url_is_the_key_when_the_entry_has_no_guid() -> None:
    item = FeedItem.build("News", "", "Title", "https://example.org/a")
    assert item is not None
    assert item.id == FeedItem.make_id("News", "https://example.org/a")


def test_html_is_stripped_from_title_and_summary() -> None:
    item = FeedItem.build(
        "News", "g",
        "<b>Patch</b> now: <script>alert(1)</script>Django &amp; friends",
        "https://example.org/a",
        summary="&lt;p&gt;Fixes <a href='javascript:x'>CVE-2024-27351</a>&lt;/p&gt;&lt;img src=x onerror=y&gt;",
    )
    assert item is not None
    assert item.title == "Patch now: Django & friends"
    assert item.summary == "Fixes CVE-2024-27351"
    assert item.cve_ids == ("CVE-2024-27351",)


def test_title_and_summary_are_capped() -> None:
    item = FeedItem.build("News", "g", "t" * 500, "https://example.org/a", summary="s" * 5000)
    assert item is not None
    assert len(item.title) == TextCleaner.TITLE_LIMIT == 200
    assert len(item.summary) == TextCleaner.SUMMARY_LIMIT == 400


@pytest.mark.parametrize("link", [
    "javascript:alert(1)", "file:///etc/passwd", "ftp://example.org/x", "data:text/html,x",
    "//example.org/x", "https://", "", "https://exa mple.org/",
])
def test_item_with_a_link_that_is_not_http_is_dropped(link: str) -> None:
    assert FeedItem.build("News", "g", "Title", link) is None


def test_http_and_https_links_are_kept() -> None:
    assert FeedItem.build("News", "g", "Title", "http://example.org/a") is not None
    assert FeedItem.build("News", "g", "Title", "https://example.org/a") is not None


def test_item_without_title_is_dropped() -> None:
    assert FeedItem.build("News", "g", "<p> </p>", "https://example.org/a") is None


def test_published_is_stored_in_utc() -> None:
    local = datetime(2026, 11, 16, 12, 0, tzinfo=timezone(timedelta(hours=2)))
    item = FeedItem.build("News", "g", "Title", "https://example.org/a", published=local)
    assert item is not None
    assert item.published == datetime(2026, 11, 16, 10, 0, tzinfo=timezone.utc)


def test_packages_and_flags_are_kept() -> None:
    item = FeedItem.build(
        "KEV", "CVE-2019-14234", "Django SQL injection", "https://example.org/a",
        cve_ids=["cve-2019-14234"], packages=[PackageRef("", "Django"), PackageRef("PyPI", " ")],
        is_known_exploited=True, severity_hint=Severity.HIGH,
    )
    assert item is not None
    assert item.cve_ids == ("CVE-2019-14234",)
    assert item.packages == (PackageRef("", "Django"),)
    assert item.is_known_exploited and item.severity_hint is Severity.HIGH


def test_relevance_orders_affects_you_first() -> None:
    ordered = sorted(Relevance, key=lambda r: r.rank)
    assert ordered == [Relevance.AFFECTS_YOU, Relevance.POSSIBLE, Relevance.GENERAL]


def test_text_direction_marks_are_removed() -> None:
    assert TextCleaner.plain("safe\u202egnp.exe") == "safegnp.exe"


def test_safe_url_host() -> None:
    assert SafeUrl.host("https://News.Example.org:8443/a?b") == "news.example.org"
    assert SafeUrl.is_https("https://example.org/") and not SafeUrl.is_https("http://example.org/")


# ---------------------------------------------------------------------------
# FeedSource with a fake fetcher
# ---------------------------------------------------------------------------

class OneLineSource(FeedSource):
    """Smallest possible source: every line of the body is a headline."""

    def __init__(self) -> None:
        super().__init__("Lines", "https://feeds.example.org/lines", "en")
        self._health = SourceHealth(self.name)

    @property
    def health(self) -> SourceHealth:
        return self._health

    def fetch(self, fetcher: Fetcher) -> List[FeedItem]:
        response = fetcher.get(self.url)
        if response.unchanged:
            return []
        lines = response.body.decode("utf-8").splitlines()
        items = [FeedItem.build(self.name, line, line, f"https://example.org/{n}")
                 for n, line in enumerate(lines)]
        return [item for item in items if item is not None]


def test_source_reads_through_the_injected_fetcher() -> None:
    source = OneLineSource()
    fetcher = FakeFetcher({source.url: b"first\nsecond"})

    items = source.fetch(fetcher)

    assert [item.title for item in items] == ["first", "second"]
    assert fetcher.urls == ["https://feeds.example.org/lines"]
    assert source.host == "feeds.example.org"


def test_source_returns_nothing_when_unchanged() -> None:
    source = OneLineSource()
    assert source.fetch(FakeFetcher({source.url: FetchResponse(status=304)})) == []


# ---------------------------------------------------------------------------
# HttpFetcher
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, body: bytes, headers: Optional[Dict[str, str]] = None, status: int = 200) -> None:
        self._body = io.BytesIO(body)
        self.status = status
        self.headers = Message()
        for name, value in (headers or {}).items():
            self.headers[name] = value

    def read(self, amount: int = -1) -> bytes:
        return self._body.read(amount)

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


class RecordingOpener:
    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.requests: List[urllib.request.Request] = []
        self.timeouts: List[float] = []

    def __call__(self, request: urllib.request.Request, timeout: float) -> Any:
        self.requests.append(request)
        self.timeouts.append(timeout)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def test_request_carries_user_agent_and_timeout() -> None:
    opener = RecordingOpener(FakeResponse(b"hello", {"ETag": '"v1"', "Last-Modified": "Mon, 16 Nov 2026 09:00:00 GMT"}))
    response = HttpFetcher(opener=opener).get("https://example.org/feed")

    request = opener.requests[0]
    assert request.get_method() == "GET"
    assert request.get_header("User-agent") == "OranovixGuardian"
    assert opener.timeouts == [10.0]
    assert request.data is None
    assert response.ok and response.body == b"hello"
    assert response.etag == '"v1"'
    assert response.last_modified == "Mon, 16 Nov 2026 09:00:00 GMT"


def test_validators_are_sent_and_304_means_unchanged() -> None:
    not_modified = urllib.error.HTTPError("https://example.org/feed", 304, "Not Modified", Message(), None)
    opener = RecordingOpener(not_modified)

    response = HttpFetcher(opener=opener).get(
        "https://example.org/feed", etag='"v1"', last_modified="Mon, 16 Nov 2026 09:00:00 GMT"
    )

    request = opener.requests[0]
    assert request.get_header("If-none-match") == '"v1"'
    assert request.get_header("If-modified-since") == "Mon, 16 Nov 2026 09:00:00 GMT"
    assert response.unchanged and response.body == b""


def test_error_status_is_returned_not_raised() -> None:
    gone = urllib.error.HTTPError("https://example.org/feed", 503, "Unavailable", Message(), None)
    response = HttpFetcher(opener=RecordingOpener(gone)).get("https://example.org/feed")
    assert response.status == 503 and not response.ok


@pytest.mark.parametrize("url", ["http://example.org/feed", "file:///etc/passwd", "ftp://example.org/", "https://"])
def test_only_https_is_requested(url: str) -> None:
    opener = RecordingOpener(FakeResponse(b"x"))
    with pytest.raises(FetchError):
        HttpFetcher(opener=opener).get(url)
    assert opener.requests == []


def test_oversize_answer_is_refused() -> None:
    opener = RecordingOpener(FakeResponse(b"x" * 101))
    with pytest.raises(FetchError, match="larger"):
        HttpFetcher(max_bytes=100, opener=opener).get("https://example.org/feed")


def test_oversize_answer_is_refused_by_its_declared_length() -> None:
    opener = RecordingOpener(FakeResponse(b"", {"Content-Length": str(6 * 1024 * 1024)}))
    with pytest.raises(FetchError, match="larger"):
        HttpFetcher(opener=opener).get("https://example.org/feed")


def test_default_cap_is_five_megabytes() -> None:
    assert HttpFetcher.MAX_BYTES == 5 * 1024 * 1024


def test_connection_failure_becomes_fetch_error() -> None:
    opener = RecordingOpener(urllib.error.URLError("name not resolved"))
    with pytest.raises(FetchError, match="name not resolved"):
        HttpFetcher(opener=opener).get("https://example.org/feed")


def test_redirect_to_plain_http_is_refused() -> None:
    fetcher = HttpFetcher()
    with pytest.raises(FetchError):
        fetcher._check_url("http://example.org/feed")


def test_uptime_mode_allows_http_and_cuts_long_answers() -> None:
    opener = RecordingOpener(FakeResponse(b"x" * 500))
    response = HttpFetcher(allow_http=True, max_bytes=100, truncate=True, opener=opener).get("http://example.org/")
    assert response.ok and len(response.body) == 100
