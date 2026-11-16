"""
Alarms for feed items that hit one of the user's projects.

Only an item that is confirmed for an installed version AND is either
exploited in the wild or rated critical is announced, once. Everything
else stays silent and is only listed on the page.
"""
from __future__ import annotations

import os
from typing import Dict, Iterable, List, Optional

from core.alarm_center import Alarm, AlarmCenter
from core.language_manager import LanguageManager
from scanner_engine.base import Issue, Severity
from scanner_engine.categories import IssueCategory

from .models import ProjectMatch, Relevance, StoredItem
from .store import ThreatStore


class ThreatAlarmRaiser:
    """Hands qualifying feed items to the alarm center, once per item and project."""

    RULE_ID = "TF001"

    def __init__(self, alarm_center: Optional[AlarmCenter], store: ThreatStore) -> None:
        self._alarm_center = alarm_center
        self._store = store

    @staticmethod
    def deserves_alarm(stored: StoredItem) -> bool:
        if stored.relevance is not Relevance.AFFECTS_YOU:
            return False
        confirmed = [match for match in stored.matches if match.confirmed]
        if not confirmed:
            return False
        return stored.item.is_known_exploited or any(
            match.severity is Severity.CRITICAL for match in confirmed
        )

    def raise_for(self, items: Iterable[StoredItem]) -> List[Alarm]:
        """Raise one CRITICAL alarm per qualifying item that has not alarmed yet."""
        if self._alarm_center is None:
            return []
        alarms: List[Alarm] = []
        for stored in items:
            if not self.deserves_alarm(stored):
                continue
            pending = [
                match for match in self._one_per_project(stored)
                if not self._store.was_alarmed(stored.id, self._project_key(match))
            ]
            if not pending:
                continue
            issues = [self.issue(stored, match) for match in pending]
            # The projects differ, so the root is left empty and the project
            # is part of each finding id instead.
            alarm = self._alarm_center.notify(issues, scan_root="", full_scan=False)
            for match in pending:
                self._store.mark_alarmed(stored.id, self._project_key(match))
            if alarm is not None:
                alarms.append(alarm)
        return alarms

    @classmethod
    def issue(cls, stored: StoredItem, match: ProjectMatch) -> Issue:
        lm = LanguageManager()
        item = stored.item
        key = "tf_alarm_exploited" if item.is_known_exploited else "tf_alarm_critical"
        title = lm.t(
            key, project=match.project, package=match.package,
            version=match.version, advisory=match.advisory_id,
        )
        fix = (
            lm.t("tf_alarm_fix", version=match.fixed_version)
            if match.fixed_version else lm.t("tf_alarm_fix_unknown")
        )
        return Issue(
            rule_id=cls.RULE_ID,
            title=title,
            description=f"{item.title} ({item.source})",
            severity=Severity.CRITICAL,
            file_path=match.file_path or match.project_path,
            line_number=match.line,
            recommendation=fix,
            confidence="HIGH",
            category=IssueCategory.DEPENDENCY,
            finding_key=f"threat-feed|{item.id}|{cls._project_key(match)}",
        )

    @staticmethod
    def _one_per_project(stored: StoredItem) -> List[ProjectMatch]:
        chosen: Dict[str, ProjectMatch] = {}
        for match in stored.matches:
            if not match.confirmed:
                continue
            key = ThreatAlarmRaiser._project_key(match)
            current = chosen.get(key)
            if current is None or (match.severity and current.severity
                                   and match.severity.weight > current.severity.weight):
                chosen[key] = match
        return list(chosen.values())

    @staticmethod
    def _project_key(match: ProjectMatch) -> str:
        return os.path.normcase(os.path.abspath(match.project_path))
