"""Integration-test fixtures (DB-backed)."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from site_b2b_intel.db.connection import open_db


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "test.db"


@pytest.fixture
def db(db_path: Path) -> Iterator[sqlite3.Connection]:
    with open_db(db_path) as conn:
        yield conn
