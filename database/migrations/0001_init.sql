CREATE TABLE IF NOT EXISTS scans (
    scan_id       TEXT PRIMARY KEY,
    status        TEXT NOT NULL CHECK (status IN ('running','completed','failed')),
    targets       TEXT NOT NULL,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at   TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_hosts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    ip            TEXT NOT NULL,
    UNIQUE (scan_id, ip)
);

CREATE TABLE IF NOT EXISTS scan_ports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_host_id  INTEGER NOT NULL REFERENCES scan_hosts(id) ON DELETE CASCADE,
    port          INTEGER NOT NULL,
    state         TEXT NOT NULL CHECK (state IN ('open','closed')),
    service       TEXT,
    banner        TEXT,
    exploits      TEXT NOT NULL DEFAULT '[]',
    UNIQUE (scan_host_id, port)
);

CREATE TABLE IF NOT EXISTS port_states (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ip            TEXT NOT NULL,
    port          INTEGER NOT NULL,
    service       TEXT,
    banner        TEXT,
    exploits      TEXT NOT NULL DEFAULT '[]',
    status        TEXT NOT NULL CHECK (status IN ('open','closed')),
    first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_scan_id  TEXT REFERENCES scans(scan_id),
    UNIQUE (ip, port)
);

CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    ip            TEXT NOT NULL,
    port          INTEGER,
    event_type    TEXT NOT NULL CHECK (event_type IN
                    ('new_host','new_open_port','port_closed','service_changed','new_exploit')),
    detail        TEXT,
    notified      INTEGER NOT NULL DEFAULT 0,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);