"""
App-wide owner of the Threat Feed and the project list.

Pages are rebuilt on every theme or language change, so nothing that
runs in the background can live in a page. The hub holds the service,
the periodic refresh and the uptime monitor, and tells listeners about
changes through ``dispatch`` (the GUI passes ``widget.after``), so it
never touches Tk itself.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, List, Optional, Sequence, Tuple

from core.alarm_center import AlarmCenter
from core.language_manager import LanguageManager
from live_defense.base import IntegrityEvent, Monitor, MonitorReport

from .digest import Digest, DigestBuilder, DigestTexts
from .fetcher import Fetcher
from .models import Relevance, SourceHealth, StoredItem
from .projects import Project, ProjectRegistry, ScanSummary, ScanSummaryLookup
from .relevance import RelevanceMatcher
from .service import RefreshReport, ThreatFeedService
from .settings import ThreatFeedConfig, ThreatFeedSettings
from .sources import SourceCatalog, SourceConfig
from .store import FeedDatabase, ThreatStore
from .uptime import UptimeCheck, UptimeEvent, UptimeMonitor, UptimeStore

Dispatch = Callable[[Callable[[], None]], object]
Spawn = Callable[[Callable[[], None]], object]


def in_thread(work: Callable[[], None]) -> None:
    threading.Thread(target=work, name="ThreatIntelWork", daemon=True).start()


@dataclass(frozen=True)
class HubState:
    """Snapshot handed to listeners."""

    enabled: bool
    asked: bool
    refreshing: bool
    last_success: Optional[datetime]
    unread_for_you: int
    database_ready: bool
    last_report: Optional[RefreshReport] = None
    uptime_event: Optional[UptimeEvent] = None      # set only on the notification it belongs to


@dataclass(frozen=True)
class ProjectRow:
    """Everything the My Projects table shows for one project."""

    project: Project
    scan: Optional[ScanSummary]
    check: Optional[UptimeCheck]
    down_since: Optional[datetime]
    affecting: int                          # unread feed items that affect it
    packages: int


Listener = Callable[[HubState], None]


class FeedRefreshMonitor(Monitor):
    """Refreshes the feed on a timer, with the thread handling of every monitor."""

    def __init__(self, refresh: Callable[[], object], interval_seconds: float) -> None:
        super().__init__("", interval_seconds)
        self._refresh = refresh

    def check(self) -> List[IntegrityEvent]:
        self._refresh()
        return []


class ThreatIntelHub:
    """Starts, stops and talks to the feed service and the uptime monitor."""

    PAGE_SIZE = 200

    def __init__(
        self,
        dispatch: Dispatch,
        alarm_center: Optional[AlarmCenter] = None,
        database: Optional[FeedDatabase] = None,
        settings: Optional[ThreatFeedSettings] = None,
        fetcher: Optional[Fetcher] = None,
        uptime_fetcher: Optional[Fetcher] = None,
        matcher: Optional[RelevanceMatcher] = None,
        scan_lookup: Optional[ScanSummaryLookup] = None,
        spawn: Spawn = in_thread,
    ) -> None:
        """*spawn* runs slow work off the caller's thread; tests run it inline."""
        self._dispatch = dispatch
        self._spawn = spawn
        database = database or FeedDatabase()
        self._store = ThreatStore(database)
        self._registry = ProjectRegistry(database)
        self._uptime_store = UptimeStore(database)
        self._settings = settings or ThreatFeedSettings()
        self._service = ThreatFeedService(
            self._store, self._registry, self._settings,
            fetcher=fetcher, matcher=matcher, alarm_center=alarm_center,
        )
        self._uptime = UptimeMonitor(
            self._registry, self._uptime_store, fetcher=uptime_fetcher,
            alarm_center=alarm_center, on_report=self._on_uptime_report,
            on_event=self._on_uptime_event,
        )
        self._scan_lookup = scan_lookup or ScanSummaryLookup()
        self._listeners: List[Listener] = []
        self._refresher: Optional[FeedRefreshMonitor] = None
        self._busy = threading.Lock()           # held while a refresh is running
        self._last_report: Optional[RefreshReport] = None
        # "New" on the page means newer than the visit before this session.
        self._session_since = self._store.last_visit()

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    @property
    def store(self) -> ThreatStore:
        return self._store

    @property
    def registry(self) -> ProjectRegistry:
        return self._registry

    @property
    def uptime_store(self) -> UptimeStore:
        return self._uptime_store

    @property
    def session_since(self) -> Optional[datetime]:
        return self._session_since

    @property
    def is_refreshing(self) -> bool:
        return self._busy.locked()

    def config(self) -> ThreatFeedConfig:
        return self._settings.load()

    def hosts(self) -> List[str]:
        """Hosts a refresh would contact, for the consent dialog."""
        return SourceCatalog.hosts(self.config().sources)

    def state(self, uptime_event: Optional[UptimeEvent] = None) -> HubState:
        config = self.config()
        return HubState(
            enabled=config.enabled,
            asked=config.asked,
            refreshing=self.is_refreshing,
            last_success=self._store.last_success(),
            unread_for_you=self._store.unread_for_you(),
            database_ready=self._service.database_ready,
            last_report=self._last_report,
            uptime_event=uptime_event,
        )

    def items(self, for_you: bool, limit: int = PAGE_SIZE) -> List[StoredItem]:
        """Items of a tab.

        "For you" always holds every item that affects a project, whatever
        its age, followed by at most *limit* guesses. "All" is the newest
        *limit* items.
        """
        if not for_you:
            return self._store.items(limit=limit, newest_first=True)
        affecting = self._store.items([Relevance.AFFECTS_YOU], limit=100000)
        return affecting + self._store.items([Relevance.POSSIBLE], limit=limit)

    def item_count(self, for_you: bool) -> int:
        """How many items the tab has in the store, shown or not."""
        relevances = [Relevance.AFFECTS_YOU, Relevance.POSSIBLE] if for_you else None
        return self._store.count(relevances)

    def source_health(self) -> List[Tuple[SourceConfig, SourceHealth]]:
        return self._service.source_health()

    def digest(self, since: Optional[datetime]) -> Digest:
        """What arrived after *since*, worded in the current language."""
        return DigestBuilder.build(
            self._store.items(limit=100000), self._registry.list(), since,
            DigestTexts.translated(LanguageManager().t),
        )

    def project_rows(self) -> List[ProjectRow]:
        unread = self._store.items([Relevance.AFFECTS_YOU], unread_only=True, limit=100000)
        rows = []
        for project in self._registry.list():
            check = self._uptime_store.latest(project.name) if project.site_url else None
            if check is not None and check.url != project.site_url:
                check = None                    # the address was changed since
            rows.append(ProjectRow(
                project=project,
                scan=self._scan_lookup.latest_for(project),
                check=check,
                down_since=(
                    self._uptime_store.down_since(project.name, project.site_url)
                    if project.site_url else None
                ),
                affecting=sum(
                    1 for item in unread if any(m.project == project.name for m in item.matches)
                ),
                packages=len(self._service.inventory(project).dependencies),
            ))
        return rows

    # ------------------------------------------------------------------
    # Listeners
    # ------------------------------------------------------------------

    def add_listener(self, listener: Listener) -> None:
        if listener not in self._listeners:
            self._listeners.append(listener)

    def remove_listener(self, listener: Listener) -> None:
        if listener in self._listeners:
            self._listeners.remove(listener)

    def notify(self, uptime_event: Optional[UptimeEvent] = None) -> None:
        """Send the current state to every listener (call on the dispatch thread)."""
        snapshot = self.state(uptime_event)
        for listener in list(self._listeners):
            try:
                listener(snapshot)
            except Exception:
                self.remove_listener(listener)      # e.g. a destroyed page

    # ------------------------------------------------------------------
    # Switching the feed on and off
    # ------------------------------------------------------------------

    def answer_first_run(self, enable: bool) -> None:
        """Record the answer of the first-run dialog."""
        self.set_enabled(enable)

    def set_enabled(self, enabled: bool) -> None:
        self._settings.update(enabled=enabled, asked=True)
        if enabled:
            self._start_refresher()
        else:
            self._stop_refresher()
        self.notify()

    def set_interval(self, minutes: object) -> int:
        config = self._settings.update(interval_minutes=ThreatFeedConfig.valid_interval(minutes))
        if self._refresher is not None:
            self._refresher.interval = config.interval_minutes * 60
        return config.interval_minutes

    def set_sources(self, sources: Sequence[SourceConfig]) -> None:
        self._settings.update(sources=tuple(sources))
        self.notify()

    # ------------------------------------------------------------------
    # Background work
    # ------------------------------------------------------------------

    def start(self) -> None:
        """App start: uptime checks always, feed refresh only when switched on."""
        self._uptime.start()
        if self.config().enabled:
            self._start_refresher()

    def shutdown(self) -> None:
        self._uptime.stop(timeout=2)
        self._stop_refresher(timeout=2)

    def refresh_async(self) -> bool:
        """Refresh in a background thread. Returns ``False`` when one is already running."""
        if self.is_refreshing:
            return False
        self._spawn(lambda: self._refresh() and None)
        return True

    def refresh_now(self) -> Optional[RefreshReport]:
        """Refresh in the caller's thread (tests, and the timer thread)."""
        return self._refresh()

    def _refresh(self) -> Optional[RefreshReport]:
        if not self._busy.acquire(blocking=False):
            return None
        try:
            self._dispatch(self.notify)                 # show "refreshing"
            self._last_report = self._service.refresh()
            return self._last_report
        finally:
            self._busy.release()
            self._dispatch(self.notify)

    def _start_refresher(self) -> None:
        if self._refresher is not None and self._refresher.is_running:
            return
        self._refresher = FeedRefreshMonitor(self._refresh, self.config().interval_minutes * 60)
        self._refresher.start()

    def _stop_refresher(self, timeout: float = 10.0) -> None:
        if self._refresher is not None:
            self._refresher.stop(timeout)
            self._refresher = None

    def _on_uptime_report(self, report: MonitorReport) -> None:
        self._dispatch(self.notify)

    def _on_uptime_event(self, event: UptimeEvent) -> None:
        self._dispatch(lambda: self.notify(event))

    # ------------------------------------------------------------------
    # Projects
    # ------------------------------------------------------------------

    def add_project(self, name: str, path: str, site_url: Optional[str] = None) -> Project:
        """Add the project at once; matching and the first site check follow in the background.

        Raises ``ProjectError`` when the values are not acceptable.
        """
        project = self._registry.add(name, path, site_url)

        def settle() -> None:
            self._service.rematch()
            if project.site_url:
                self._uptime.check_project(project)
            self._dispatch(self.notify)

        self._spawn(settle)
        return project

    def remove_project(self, name: str) -> None:
        if not self._registry.remove(name):
            return
        self._uptime_store.forget(name)

        def settle() -> None:
            self._service.rematch()
            self._dispatch(self.notify)

        self._spawn(settle)

    def check_sites_now(self) -> None:
        """One uptime cycle in the caller's thread."""
        self._uptime.check_sites()
