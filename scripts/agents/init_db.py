"""Initialize the SQLite coordination database.

Creates build/coordination.sqlite with three tables matching the schema
in notes/agent-task-schema.md: tasks, evidence_log, agent_runs.

Idempotent — uses CREATE TABLE IF NOT EXISTS.

Usage:
    python scripts/agents/init_db.py --db build/coordination.sqlite
"""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path


SCHEMA_SQL = """
-- The task queue. Workers poll this table for pending work.
CREATE TABLE IF NOT EXISTS tasks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kind            TEXT NOT NULL CHECK (kind IN (
                        'propose_name', 'propose_contract',
                        'classify_register', 'describe_function',
                        'resolve_conflict', 'trace_data_source'
                    )),
    target          TEXT NOT NULL,
    entity_addr     INTEGER NOT NULL,
    priority        REAL NOT NULL DEFAULT 0,
    round           INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
                        'pending', 'claimed', 'completed', 'failed'
                    )),
    lease_holder    TEXT,
    lease_expires   TEXT,
    payload_json    TEXT,
    depends_on      INTEGER REFERENCES tasks(id),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    completed_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_tasks_poll ON tasks (status, priority DESC)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_tasks_lease ON tasks (lease_expires)
    WHERE status = 'claimed';


-- Append-only evidence log. Every agent proposal lands here.
CREATE TABLE IF NOT EXISTS evidence_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER REFERENCES tasks(id),
    target          TEXT NOT NULL,
    entity_addr     INTEGER NOT NULL,
    agent_id        TEXT NOT NULL,
    claim_type      TEXT NOT NULL CHECK (claim_type IN (
                        'name', 'contract', 'register_role', 'description',
                        'data_trace'
                    )),
    claim_json      TEXT NOT NULL,
    confidence      REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    evidence_method TEXT NOT NULL,
    round           INTEGER NOT NULL DEFAULT 0,
    supersedes_id   INTEGER REFERENCES evidence_log(id),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_evidence_entity ON evidence_log (target, entity_addr, claim_type);
CREATE INDEX IF NOT EXISTS idx_evidence_task   ON evidence_log (task_id);


-- Agent run accounting. One row per worker invocation.
CREATE TABLE IF NOT EXISTS agent_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id        TEXT NOT NULL,
    model           TEXT NOT NULL,
    task_id         INTEGER REFERENCES tasks(id),
    started_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    completed_at    TEXT,
    input_tokens    INTEGER,
    output_tokens   INTEGER,
    cost_usd        REAL
);

CREATE INDEX IF NOT EXISTS idx_runs_agent ON agent_runs (agent_id);
"""


def main():
    parser = argparse.ArgumentParser(
        description="Initialize the SQLite coordination database"
    )
    parser.add_argument("--db", required=True, help="Path to coordination.sqlite")
    args = parser.parse_args()

    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA_SQL)
    conn.close()

    print(f"init_db: created/verified {db_path} with tables: tasks, evidence_log, agent_runs")


if __name__ == "__main__":
    main()
