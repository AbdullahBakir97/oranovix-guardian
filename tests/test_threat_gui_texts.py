"""Texts of the Threat Feed and My Projects pages. No window is opened."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, List, Set

import pytest

from core.language_manager import LanguageManager
from scanner_engine.base import Severity
from threat_intel.hub import HubState, ProjectRow
from threat_intel.models import FeedItem, ProjectMatch, Relevance, SourceHealth, StoredItem
from threat_intel.projects import Project, ScanSummary
from threat_intel.service import RefreshReport
from threat_intel.sources import SourceConfig
from threat_intel.uptime import UptimeCheck

ROOT = Path(__file__).parent.parent
TRANSLATIONS = ROOT / "translations"
NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
SOURCES = [
    ROOT / "gui" / "pages" / "threat_feed_page.py",
    ROOT / "gui" / "pages" / "projects_page.py",
    ROOT / "gui" / "threat_feed_dialogs.py",
    ROOT / "gui" / "pages" / "settings_page.py",
    ROOT / "threat_intel" / "alarms.py",
    ROOT / "threat_intel" / "uptime.py",
]
KEY = re.compile(r"""['"]((?:tf|proj|up|digest)_[a-z_]+)['"]""")


def used_keys() -> Set[str]:
    keys: Set[str] = {"nav_threat_feed", "nav_projects"}
    for path in SOURCES:
        keys.update(KEY.findall(path.read_text(encoding="utf-8")))
    keys.update(f"tf_tab_{tab}" for tab in ("for_you", "all", "sources"))
    keys.update(f"tf_badge_{relevance.value}" for relevance in Relevance)
    keys.update(f"digest_{name}" for name in (
        "headline", "nothing_new", "affecting", "possible", "other", "more",
        "exploited", "fix", "projects", "project_line", "project_clear",
    ))
    return {key for key in keys if not key.endswith("_")}


@pytest.fixture
def english() -> Iterator[LanguageManager]:
    lm = LanguageManager()
    before = lm.current_lang
    lm.set_language("en")
    yield lm
    lm.set_language(before)


@pytest.mark.parametrize("language", ["en", "de", "ar"])
def test_every_text_exists_in_every_language(language: str) -> None:
    texts = json.loads((TRANSLATIONS / f"{language}.json").read_text(encoding="utf-8"))
    missing = sorted(key for key in used_keys() if not texts.get(key))
    assert missing == [], f"{language}: {missing}"


@pytest.mark.parametrize("language", ["de", "ar"])
def test_translations_keep_the_placeholders(language: str) -> None:
    english_texts = json.loads((TRANSLATIONS / "en.json").read_text(encoding="utf-8"))
    texts = json.loads((TRANSLATIONS / f"{language}.json").read_text(encoding="utf-8"))
    placeholder = re.compile(r"\{[a-z_]+\}")
    for key in used_keys():
        assert set(placeholder.findall(texts[key])) == set(placeholder.findall(english_texts[key])), key


@pytest.mark.parametrize("language", ["en", "de", "ar"])
def test_consent_dialog_names_every_host(language: str) -> None:
    from gui.threat_feed_dialogs import FeedConsentDialog

    lm = LanguageManager()
    before = lm.current_lang
    lm.set_language(language)
    try:
        text = FeedConsentDialog.consent_text(["www.cisa.gov", "wid.cert-bund.de"])
    finally:
        lm.set_language(before)
    assert "www.cisa.gov" in text and "wid.cert-bund.de" in text


def test_link_question_shows_the_domain(english: LanguageManager) -> None:
    from gui.threat_feed_dialogs import LinkOpener

    title, text = LinkOpener.question("https://news.example.org/story?id=7")
    assert title == "Open link?"
    assert text == "This opens news.example.org in your browser."


def test_link_that_is_not_a_web_link_is_never_opened(english: LanguageManager) -> None:
    from gui.threat_feed_dialogs import LinkOpener

    opened: List[str] = []
    assert LinkOpener.open(None, "javascript:alert(1)", browser=opened.append) is False
    assert opened == []


# ---------------------------------------------------------------------------
# Threat Feed page
# ---------------------------------------------------------------------------

MATCH = ProjectMatch(
    project="Shop", project_path="/srv/shop", package="Django", ecosystem="PyPI", version="2.2.0",
    advisory_id="CVE-2019-14234", severity=Severity.CRITICAL, fixed_version="2.2.4",
)


def stored(relevance: Relevance, matches: tuple = ()) -> StoredItem:
    item = FeedItem("id", "CISA KEV", "Title", "https://example.org/a",
                    datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc))
    return StoredItem(item, NOW, False, relevance, matches)


def state(**changes: object) -> HubState:
    values = dict(enabled=True, asked=True, refreshing=False, last_success=NOW,
                  unread_for_you=0, database_ready=True)
    values.update(changes)
    return HubState(**values)        # type: ignore[arg-type]


def test_feed_row_shows_which_project_and_package_matched(english: LanguageManager) -> None:
    from gui.pages.threat_feed_page import ThreatFeedPage

    lines = ThreatFeedPage.match_lines(stored(Relevance.AFFECTS_YOU, (MATCH,)))
    assert lines == ["Shop: Django 2.2.0 (CVE-2019-14234)  →  fixed in 2.2.4"]
    assert ThreatFeedPage.badge_text(Relevance.AFFECTS_YOU) == "AFFECTS YOU"
    assert ThreatFeedPage.meta_text(stored(Relevance.GENERAL)).startswith("CISA KEV  ·  2026-11-1")


def test_possible_match_is_labelled_as_a_guess(english: LanguageManager) -> None:
    from gui.pages.threat_feed_page import ThreatFeedPage

    guess = ProjectMatch("Blog", "/srv/blog", "lodash", "npm", "4.17.21")
    lines = ThreatFeedPage.match_lines(stored(Relevance.POSSIBLE, (guess,)))
    assert lines == ["Possible match, verify:", "Blog: lodash 4.17.21"]
    assert ThreatFeedPage.match_lines(stored(Relevance.GENERAL)) == []


def test_page_says_when_the_last_successful_update_was(english: LanguageManager) -> None:
    from gui.pages.threat_feed_page import ThreatFeedPage

    local = NOW.astimezone().strftime("%Y-%m-%d %H:%M")
    assert ThreatFeedPage.updated_text(state()) == f"Last successful update: {local}"
    assert ThreatFeedPage.updated_text(state(last_success=None)) == "Not updated yet"

    offline = RefreshReport(NOW + timedelta(hours=3), failures=("News: no route to host",))
    assert ThreatFeedPage.updated_text(state(last_report=offline)) == (
        f"Offline, showing saved items.  Last successful update: {local}"
    )


def test_notes_above_the_list(english: LanguageManager) -> None:
    from gui.pages.threat_feed_page import ThreatFeedPage

    assert "My Projects" in ThreatFeedPage.note_text(state(), has_projects=False)
    assert "database is missing" in ThreatFeedPage.note_text(state(database_ready=False), has_projects=True)
    assert ThreatFeedPage.note_text(state(), has_projects=True) == ""


def test_source_status(english: LanguageManager) -> None:
    from gui.pages.threat_feed_page import ThreatFeedPage

    on = SourceConfig("News", "https://news.example.org/feed")
    off = SourceConfig("News", "https://news.example.org/feed", enabled=False)
    assert ThreatFeedPage.source_status(on, SourceHealth("News", NOW)) == ("OK", "success")
    assert ThreatFeedPage.source_status(on, SourceHealth("News", None, "timed out", NOW)) == ("timed out", "error")
    assert ThreatFeedPage.source_status(on, SourceHealth("News")) == ("never", "text3")
    assert ThreatFeedPage.source_status(off, SourceHealth("News", NOW)) == ("disabled", "text3")


# ---------------------------------------------------------------------------
# My Projects page
# ---------------------------------------------------------------------------

def row(**changes: object) -> ProjectRow:
    values = dict(project=Project("Shop", "/srv/shop", "https://shop.example.org/"), scan=None,
                  check=None, down_since=None, affecting=0, packages=5)
    values.update(changes)
    return ProjectRow(**values)      # type: ignore[arg-type]


def test_project_scan_cell(english: LanguageManager) -> None:
    from gui.pages.projects_page import ProjectsPage

    assert ProjectsPage.scan_text(row()) == ("Never scanned", "text3")
    scanned = row(scan=ScanSummary(datetime(2026, 11, 15, 17, 45), 1, 2, 5, 80))
    assert ProjectsPage.scan_text(scanned) == ("2026-11-15 17:45\nCritical 1, High 2", "critical")
    clean = row(scan=ScanSummary(datetime(2026, 11, 15, 17, 45), 0, 0, 0, 0))
    assert ProjectsPage.scan_text(clean)[1] == "success"


def test_project_site_cell(english: LanguageManager) -> None:
    from gui.pages.projects_page import ProjectsPage

    url = "https://shop.example.org/"
    up = UptimeCheck("Shop", url, NOW, ok=True, status=200, response_ms=87)
    failed = UptimeCheck("Shop", url, NOW, ok=False, error="connection refused")

    assert ProjectsPage.site_text(row(project=Project("Lib", "/srv/lib"))) == ("No site", "text3")
    assert ProjectsPage.site_text(row()) == (f"{url}\nNot checked yet", "text3")
    assert ProjectsPage.site_text(row(check=up)) == (f"{url}\nUp (HTTP 200)", "success")
    assert ProjectsPage.response_text(row(check=up)) == "87 ms"
    assert ProjectsPage.site_text(row(check=failed)) == (f"{url}\nCheck failed: connection refused", "warning")
    assert ProjectsPage.response_text(row(check=failed)) == "—"

    down_text, level = ProjectsPage.site_text(row(check=failed, down_since=NOW))
    assert down_text.startswith(f"{url}\nDown since ") and level == "error"


def test_project_feed_badge(english: LanguageManager) -> None:
    from gui.pages.projects_page import ProjectsPage

    assert ProjectsPage.feed_text(row(affecting=2)) == ("2 affect it", "critical")
    assert ProjectsPage.feed_text(row()) == ("Nothing", "text3")
    assert ProjectsPage.path_text(row()).endswith("5 packages")
