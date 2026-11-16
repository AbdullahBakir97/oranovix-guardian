"""Shared fixtures: a tiny OSV database built from ``tests/fixtures/osv``."""
from __future__ import annotations

import json
import socket
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

import pytest

from scanner_engine.deps.osv_db import OSVDatabase
from scanner_engine.deps.versions import Ecosystem

OSV_FIXTURES = Path(__file__).parent / "fixtures" / "osv"


@pytest.fixture
def osv_records() -> Dict[Ecosystem, List[Dict[str, Any]]]:
    return {
        ecosystem: json.loads((OSV_FIXTURES / f"{ecosystem.value}.json").read_text("utf-8"))
        for ecosystem in Ecosystem
    }


@pytest.fixture
def osv_db(tmp_path: Path, osv_records: Dict[Ecosystem, List[Dict[str, Any]]]) -> OSVDatabase:
    database = OSVDatabase(str(tmp_path / "osv.db"))
    database.import_records(osv_records)
    return database


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any attempt to open a connection fails the test."""
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("network access during a test")

    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
