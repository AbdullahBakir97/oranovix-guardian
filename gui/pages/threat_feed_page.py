"""
Threat Feed page: security news and exploited vulnerabilities, with the
items that concern the user's projects first.

The page only shows what the local store holds. Refreshing runs in the
hub's background thread; the page is redrawn from the state the hub
sends, so the window never waits for the network.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Optional, Sequence, Tuple

import customtkinter as ctk

from core.language_manager import LanguageManager
from gui.theme_manager import ThemeManager
from gui.threat_feed_dialogs import FeedConsentDialog, LinkOpener
from threat_intel.hub import HubState, ThreatIntelHub
from threat_intel.models import ProjectMatch, Relevance, SourceHealth, StoredItem
from threat_intel.sources import SourceConfig


class ThreatFeedPage(ctk.CTkFrame):
    """Sidebar page "Threat Feed" with the tabs For you, All and Sources."""

    TABS = ("for_you", "all", "sources")

    _BADGE_COLORS = {
        Relevance.AFFECTS_YOU: "critical",
        Relevance.POSSIBLE: "warning",
        Relevance.GENERAL: "text3",
    }

    def __init__(
        self,
        master,
        hub: ThreatIntelHub,
        **kwargs,
    ) -> None:
        tm = ThemeManager()
        super().__init__(master, fg_color=tm.c("bg"), corner_radius=0, **kwargs)
        self._hub = hub
        self._tab = "for_you"
        # Rows per tab; "Show more" adds another page.
        self._limits: Dict[str, int] = {"for_you": hub.PAGE_SIZE, "all": hub.PAGE_SIZE}
        self._state: Optional[HubState] = None
        self._shown_key: Tuple[object, ...] = ()
        self._build()
        hub.add_listener(self._show_state)
        self._show_state(hub.state())

    def destroy(self) -> None:
        self._hub.remove_listener(self._show_state)
        super().destroy()

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build(self) -> None:
        tm = ThemeManager()
        lm = LanguageManager()
        side, far = lm.pack_side, lm.opposite_side

        hdr = ctk.CTkFrame(self, fg_color=tm.c("bg2"), corner_radius=0, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(
            hdr, text=f"  \U0001f4e1  {lm.t('tf_title')}",
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color=tm.c("text"), fg_color="transparent",
        ).pack(side=side, padx=16, fill="y")
        self._refresh_btn = self._button(hdr, lm.t("tf_refresh"), self._refresh)
        self._refresh_btn.pack(side=far, padx=16)
        self._updated_lbl = ctk.CTkLabel(
            hdr, text="", font=ctk.CTkFont(size=10), text_color=tm.c("text3"),
            fg_color="transparent",
        )
        self._updated_lbl.pack(side=far, padx=(0, 4))

        body = ctk.CTkFrame(self, fg_color=tm.c("bg"), corner_radius=0)
        body.pack(fill="both", expand=True, padx=20, pady=12)

        self._digest_lbl = ctk.CTkLabel(
            body, text="", font=ctk.CTkFont(size=12, weight="bold"), text_color=tm.c("text"),
            fg_color="transparent", anchor=lm.text_anchor,
        )
        self._digest_lbl.pack(fill="x", pady=(0, 6))

        # Shown while the feed is switched off.
        self._off_bar = ctk.CTkFrame(body, fg_color=tm.c("card"), corner_radius=8,
                                     border_width=1, border_color=tm.c("border"))
        ctk.CTkLabel(
            self._off_bar, text=lm.t("tf_off_banner"), font=ctk.CTkFont(size=11),
            text_color=tm.c("warning"), fg_color="transparent", anchor=lm.text_anchor,
            wraplength=560, justify=lm.text_justify,
        ).pack(side=side, padx=12, pady=8, fill="x", expand=True)
        self._button(self._off_bar, lm.t("tf_switch_on"), self._switch_on).pack(side=far, padx=12)

        self._note_lbl = ctk.CTkLabel(
            body, text="", font=ctk.CTkFont(size=10), text_color=tm.c("warning"),
            fg_color="transparent", anchor=lm.text_anchor, wraplength=760, justify=lm.text_justify,
        )

        bar = ctk.CTkFrame(body, fg_color="transparent")
        bar.pack(fill="x", pady=(0, 6))
        self._bar = bar
        self._tab_btns: Dict[str, ctk.CTkButton] = {}
        for key in self.TABS:
            btn = ctk.CTkButton(
                bar, text=lm.t(f"tf_tab_{key}"), width=110, height=26, corner_radius=6,
                font=ctk.CTkFont(size=10, weight="bold"), hover_color=tm.c("accent_h"),
                command=lambda k=key: self._set_tab(k),
            )
            btn.pack(side=side, padx=2)
            self._tab_btns[key] = btn
        self._read_all_btn = self._button(bar, lm.t("tf_mark_all_read"), self._mark_all_read, primary=False)
        self._read_all_btn.pack(side=far)

        self._list = ctk.CTkScrollableFrame(body, fg_color=tm.c("bg"), corner_radius=0)
        self._list.pack(fill="both", expand=True)
        self._paint_tabs()

    @staticmethod
    def _button(master, text: str, command: Callable[[], None], primary: bool = True) -> ctk.CTkButton:
        tm = ThemeManager()
        return ctk.CTkButton(
            master, text=text, height=28, corner_radius=6, command=command,
            width=max(110, 8 * len(text)), font=ctk.CTkFont(size=10),
            fg_color=tm.c("accent") if primary else tm.c("bg3"),
            hover_color=tm.c("accent_h") if primary else tm.c("hover"),
            text_color="#ffffff" if primary else tm.c("text2"),
        )

    # ------------------------------------------------------------------
    # State from the hub
    # ------------------------------------------------------------------

    def _show_state(self, state: HubState) -> None:
        lm = LanguageManager()
        self._state = state

        self._updated_lbl.configure(text=self.updated_text(state))
        self._refresh_btn.configure(
            text=lm.t("tf_refreshing") if state.refreshing else lm.t("tf_refresh"),
            state="disabled" if state.refreshing else "normal",
        )
        self._digest_lbl.configure(text=self._hub.digest(self._hub.session_since).headline)

        if state.enabled:
            self._off_bar.pack_forget()
        elif not self._off_bar.winfo_ismapped():
            self._off_bar.pack(fill="x", pady=(0, 8), before=self._bar)

        note = self.note_text(state, has_projects=bool(self._hub.registry.list()))
        self._note_lbl.configure(text=note)
        if note and not self._note_lbl.winfo_ismapped():
            self._note_lbl.pack(fill="x", pady=(0, 6), before=self._bar)
        elif not note:
            self._note_lbl.pack_forget()

        self._render()

    @staticmethod
    def updated_text(state: HubState) -> str:
        lm = LanguageManager()
        if state.last_success is None:
            return lm.t("tf_never_updated")
        local = state.last_success.astimezone()
        text = lm.t("tf_last_update", time=local.strftime("%Y-%m-%d %H:%M"))
        report = state.last_report
        if report is not None and report.offline:
            text = f"{lm.t('tf_offline')}  {text}"
        return text

    @staticmethod
    def note_text(state: HubState, has_projects: bool) -> str:
        """Hints above the list: no projects yet, or no vulnerability database."""
        lm = LanguageManager()
        notes = []
        if not has_projects:
            notes.append(lm.t("tf_no_projects_hint"))
        elif not state.database_ready:
            notes.append(lm.t("tf_db_missing"))
        return "\n".join(notes)

    # ------------------------------------------------------------------
    # Tabs and list
    # ------------------------------------------------------------------

    def _set_tab(self, tab: str) -> None:
        self._tab = tab
        self._paint_tabs()
        self._render(force=True)

    def _paint_tabs(self) -> None:
        tm = ThemeManager()
        for key, btn in self._tab_btns.items():
            active = key == self._tab
            btn.configure(
                fg_color=tm.c("accent") if active else tm.c("bg3"),
                text_color="#ffffff" if active else tm.c("text2"),
            )

    def _render(self, force: bool = False) -> None:
        if self._tab == "sources":
            health = self._hub.source_health()
            key: Tuple[object, ...] = ("sources", tuple((c, h) for c, h in health))
            if key == self._shown_key and not force:
                return
            self._shown_key = key
            self._clear()
            self._read_all_btn.configure(state="disabled")
            self._render_sources(health)
            return

        for_you = self._tab == "for_you"
        items = self._hub.items(for_you, self._limits[self._tab])
        hidden = self._hub.item_count(for_you) - len(items)
        key = (self._tab, hidden, tuple((i.id, i.read, i.relevance, i.matches) for i in items))
        if key == self._shown_key and not force:
            return
        self._shown_key = key
        self._clear()
        self._read_all_btn.configure(
            state="normal" if any(not i.read for i in items) else "disabled"
        )

        tm = ThemeManager()
        lm = LanguageManager()
        if not items:
            empty = lm.t("tf_empty_for_you") if self._tab == "for_you" else lm.t("tf_empty_all")
            ctk.CTkLabel(self._list, text=empty, font=ctk.CTkFont(size=12),
                         text_color=tm.c("text3")).pack(pady=28)
            return
        for item in items:
            self._item_row(item)
        if hidden > 0:
            self._button(
                self._list, lm.t("tf_show_more", count=hidden), self._show_more, primary=False
            ).pack(pady=8)

    def _show_more(self) -> None:
        self._limits[self._tab] += self._hub.PAGE_SIZE
        self._render(force=True)

    def _clear(self) -> None:
        for child in self._list.winfo_children():
            child.destroy()

    def _item_row(self, stored: StoredItem) -> None:
        tm = ThemeManager()
        lm = LanguageManager()
        side, far = lm.pack_side, lm.opposite_side
        item = stored.item

        row = ctk.CTkFrame(self._list, fg_color=tm.c("card"), corner_radius=8,
                           border_width=1, border_color=tm.c("border"))
        row.pack(fill="x", pady=3, padx=(0, 6))

        top = ctk.CTkFrame(row, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(8, 0))
        ctk.CTkLabel(
            top, text=f" {self.badge_text(stored.relevance)} ", corner_radius=4,
            fg_color=tm.c(self._BADGE_COLORS[stored.relevance]), text_color="#ffffff",
            font=ctk.CTkFont(size=9, weight="bold"),
        ).pack(side=side)
        if item.is_known_exploited:
            ctk.CTkLabel(
                top, text=f" {lm.t('tf_exploited')} ", corner_radius=4,
                fg_color=tm.c("high"), text_color="#ffffff",
                font=ctk.CTkFont(size=9, weight="bold"),
            ).pack(side=side, padx=4)
        ctk.CTkLabel(
            top, text=self.meta_text(stored), font=ctk.CTkFont(size=10),
            text_color=tm.c("text3"), fg_color="transparent",
        ).pack(side=side, padx=8)

        buttons = ctk.CTkFrame(top, fg_color="transparent")
        buttons.pack(side=far)
        if not stored.read:
            ctk.CTkButton(
                buttons, text=lm.t("tf_mark_read"), width=84, height=22, corner_radius=4,
                font=ctk.CTkFont(size=9), fg_color=tm.c("bg3"), hover_color=tm.c("hover"),
                text_color=tm.c("text2"), command=lambda i=stored.id: self._mark_read(i),
            ).pack(side=far, padx=(4, 0))
        ctk.CTkButton(
            buttons, text=lm.t("tf_open_link"), width=84, height=22, corner_radius=4,
            font=ctk.CTkFont(size=9), fg_color=tm.c("accent"), hover_color=tm.c("accent_h"),
            text_color="#ffffff", command=lambda s=stored: self._open(s),
        ).pack(side=far)

        ctk.CTkLabel(
            row, text=item.title, wraplength=720, justify=lm.text_justify, anchor=lm.text_anchor,
            font=ctk.CTkFont(size=12, weight="normal" if stored.read else "bold"),
            text_color=tm.c("text2") if stored.read else tm.c("text"), fg_color="transparent",
        ).pack(fill="x", padx=10, pady=(4, 0 if self.match_lines(stored) else 9))

        lines = self.match_lines(stored)
        if lines:
            color = tm.c("critical") if stored.relevance is Relevance.AFFECTS_YOU else tm.c("warning")
            ctk.CTkLabel(
                row, text="\n".join(lines), wraplength=720, justify=lm.text_justify,
                anchor=lm.text_anchor, font=ctk.CTkFont(size=10, weight="bold"),
                text_color=color, fg_color="transparent",
            ).pack(fill="x", padx=10, pady=(2, 9))

    @staticmethod
    def badge_text(relevance: Relevance) -> str:
        return LanguageManager().t(f"tf_badge_{relevance.value}")

    @staticmethod
    def meta_text(stored: StoredItem) -> str:
        """Source and date, e.g. ``CISA KEV  ·  2026-11-10``."""
        published = stored.item.published
        if published is None:
            return stored.item.source
        return f"{stored.item.source}  ·  {published.astimezone().strftime('%Y-%m-%d')}"

    @classmethod
    def match_lines(cls, stored: StoredItem, limit: int = 4) -> List[str]:
        """Which project and package matched; a guess is labelled as one."""
        lm = LanguageManager()
        lines = [cls._match_line(match) for match in stored.matches[:limit]]
        hidden = len(stored.matches) - limit
        if hidden > 0:
            lines.append(lm.t("tf_more_matches", count=hidden))
        if lines and stored.relevance is Relevance.POSSIBLE:
            lines.insert(0, lm.t("tf_possible_hint"))
        return lines

    @staticmethod
    def _match_line(match: ProjectMatch) -> str:
        lm = LanguageManager()
        line = lm.t(
            "tf_match_line", project=match.project, package=match.package, version=match.version
        ).rstrip()
        if match.advisory_id:
            line += f" ({match.advisory_id})"
        if match.fixed_version:
            line += "  →  " + lm.t("tf_match_fix", version=match.fixed_version)
        return line

    def _render_sources(self, health: Sequence[Tuple[SourceConfig, SourceHealth]]) -> None:
        tm = ThemeManager()
        lm = LanguageManager()
        side = lm.pack_side
        columns = [
            (lm.t("tf_src_name"), 150), (lm.t("tf_src_host"), 190), (lm.t("tf_src_language"), 70),
            (lm.t("tf_src_last_success"), 130), (lm.t("tf_src_status"), 220),
        ]
        header = ctk.CTkFrame(self._list, fg_color=tm.c("bg2"), corner_radius=4)
        header.pack(fill="x", pady=(0, 2))
        for text, width in columns:
            ctk.CTkLabel(header, text=text, width=width, anchor=lm.text_anchor,
                         font=ctk.CTkFont(size=9, weight="bold"),
                         text_color=tm.c("text3")).pack(side=side, padx=4)
        for config, state in health:
            status, level = self.source_status(config, state)
            success = (
                state.last_success.astimezone().strftime("%Y-%m-%d %H:%M")
                if state.last_success else lm.t("tf_src_never")
            )
            row = ctk.CTkFrame(self._list, fg_color=tm.c("card"), corner_radius=4)
            row.pack(fill="x", pady=1)
            cells = [
                (config.name, 150, tm.c("text")), (config.host, 190, tm.c("text2")),
                (config.language.upper(), 70, tm.c("text2")), (success, 130, tm.c("text2")),
                (status, 220, tm.c(level)),
            ]
            for text, width, color in cells:
                ctk.CTkLabel(row, text=text, width=width, anchor=lm.text_anchor, wraplength=width,
                             justify=lm.text_justify, font=ctk.CTkFont(size=10),
                             text_color=color).pack(side=side, padx=4, pady=4)

    @staticmethod
    def source_status(config: SourceConfig, health: SourceHealth) -> Tuple[str, str]:
        """Status text of a source and the theme colour for it."""
        lm = LanguageManager()
        if not config.enabled:
            return lm.t("tf_src_disabled"), "text3"
        if health.ok:
            return lm.t("tf_src_ok"), "success"
        if health.last_error:
            return health.last_error, "error"
        return lm.t("tf_src_never"), "text3"

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        if not self._hub.config().enabled:
            self._switch_on()
            return
        self._hub.refresh_async()

    def _switch_on(self) -> None:
        """The same question as on first run; nothing is contacted without a yes."""
        if FeedConsentDialog.ask(self, self._hub.hosts()):
            self._hub.set_enabled(True)
        else:
            self._hub.set_enabled(False)

    def _mark_read(self, item_id: str) -> None:
        self._hub.store.mark_read([item_id])
        self._hub.notify()

    def _mark_all_read(self) -> None:
        relevances = [Relevance.AFFECTS_YOU, Relevance.POSSIBLE] if self._tab == "for_you" else None
        self._hub.store.mark_all_read(relevances)
        self._hub.notify()

    def _open(self, stored: StoredItem) -> None:
        if LinkOpener.open(self, stored.item.url):
            self._mark_read(stored.id)

    def on_shown(self) -> None:
        """The user opened the page: from now on "new" means newer than this visit."""
        self._hub.store.set_last_visit()

    def refresh_theme(self) -> None:
        self.configure(fg_color=ThemeManager().c("bg"))
