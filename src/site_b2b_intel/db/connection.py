"""SQLite connection helper.

Opens a connection with project-standard PRAGMAs applied and the schema
loaded (idempotently), then yields the connection via a context manager.
The schema lives in ``schema.sql`` next to this file.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


@contextmanager
def open_db(path: Path | str) -> Iterator[sqlite3.Connection]:
    """Open a SQLite connection with PRAGMAs + schema applied.

    Creates parent directories on demand. Foreign keys are enforced and
    WAL mode is enabled. The schema is idempotent, so running this on an
    existing DB just re-applies the no-op DDL.

    Args:
        path: Filesystem path to the SQLite database. ``':memory:'`` is also
            accepted for in-process databases.

    Yields:
        ``sqlite3.Connection`` with ``row_factory`` set to ``sqlite3.Row``.

    Example:
        >>> with open_db('/tmp/test.db') as conn:  # doctest: +SKIP
        ...     conn.execute("SELECT COUNT(*) FROM vendor").fetchone()
    """
    path_obj = Path(path) if path != ":memory:" else None
    if path_obj is not None:
        path_obj.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path))
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")

        with _SCHEMA_PATH.open() as f:
            conn.executescript(f.read())

        yield conn
    finally:
        conn.close()
