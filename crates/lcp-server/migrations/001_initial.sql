PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE publications (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid            TEXT    NOT NULL UNIQUE,
    alt_id          TEXT,
    provider        TEXT,
    content_type    TEXT    NOT NULL DEFAULT 'application/epub+zip',
    title           TEXT    NOT NULL,
    description     TEXT,
    authors         TEXT,
    publishers      TEXT,
    cover_url       TEXT,
    encryption_key  BLOB    NOT NULL,
    file_path       TEXT    NOT NULL,
    file_size       INTEGER NOT NULL DEFAULT 0,
    checksum        TEXT    NOT NULL,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    deleted_at      TEXT
);
CREATE INDEX idx_publications_alt_id ON publications(alt_id);
CREATE INDEX idx_publications_content_type ON publications(content_type);

CREATE TABLE license_info (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid            TEXT    NOT NULL UNIQUE,
    provider        TEXT    NOT NULL,
    user_id         TEXT    NOT NULL,
    publication_id  TEXT    NOT NULL,
    start_date      TEXT,
    end_date        TEXT,
    max_end_date    TEXT,
    copy_limit      INTEGER NOT NULL DEFAULT -1,
    print_limit     INTEGER NOT NULL DEFAULT -1,
    status          TEXT    NOT NULL DEFAULT 'ready',
    status_updated  TEXT,
    device_count    INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    deleted_at      TEXT
);
CREATE INDEX idx_license_info_user_id ON license_info(user_id);
CREATE INDEX idx_license_info_publication_id ON license_info(publication_id);
CREATE INDEX idx_license_info_status ON license_info(status);

CREATE TABLE events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id  TEXT    NOT NULL,
    event_type  TEXT    NOT NULL,
    device_id   TEXT,
    device_name TEXT,
    timestamp   TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_events_license_id ON events(license_id);
CREATE INDEX idx_events_device_id ON events(device_id);
