-- Initial schema. See ../schema.sql for the canonical cumulative DDL.
-- This file is kept for migration tooling that expects per-version SQL.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS vendor (
    id INTEGER PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS vendor_profile (
    id INTEGER PRIMARY KEY,
    vendor_id INTEGER NOT NULL REFERENCES vendor(id) ON DELETE CASCADE,
    valid_from TEXT NOT NULL,
    website TEXT,
    support_email TEXT,
    sales_email TEXT,
    phone TEXT,
    headquarters TEXT,
    source TEXT,
    UNIQUE(vendor_id, valid_from)
);

CREATE TABLE IF NOT EXISTS fingerprint_rule (
    id INTEGER PRIMARY KEY,
    vendor_id INTEGER NOT NULL REFERENCES vendor(id) ON DELETE CASCADE,
    record_type TEXT NOT NULL,
    match_kind TEXT NOT NULL CHECK (match_kind IN ('prefix','suffix','contains','exact','regex')),
    pattern TEXT NOT NULL,
    confidence TEXT NOT NULL CHECK (confidence IN ('low','medium','high')),
    enabled INTEGER NOT NULL DEFAULT 1,
    UNIQUE(vendor_id, record_type, match_kind, pattern)
);
CREATE INDEX IF NOT EXISTS idx_rule_record_type ON fingerprint_rule(record_type, enabled);

CREATE TABLE IF NOT EXISTS scan (
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL,
    domain_normalized TEXT NOT NULL,
    scanned_at TEXT NOT NULL DEFAULT (datetime('now')),
    resolver_used TEXT,
    dns_seconds REAL,
    flags INTEGER NOT NULL DEFAULT 0,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_domain ON scan(domain_normalized, scanned_at);

CREATE TABLE IF NOT EXISTS dns_record (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    record_type TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER,
    source TEXT NOT NULL DEFAULT 'direct',
    parent_record_id INTEGER REFERENCES dns_record(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_dns_record_scan ON dns_record(scan_id, record_type);

CREATE TABLE IF NOT EXISTS detection (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    vendor_id INTEGER NOT NULL REFERENCES vendor(id) ON DELETE CASCADE,
    rule_id INTEGER NOT NULL REFERENCES fingerprint_rule(id) ON DELETE CASCADE,
    confidence TEXT NOT NULL CHECK (confidence IN ('low','medium','high')),
    UNIQUE(scan_id, vendor_id, rule_id)
);
CREATE INDEX IF NOT EXISTS idx_detection_scan ON detection(scan_id);
CREATE INDEX IF NOT EXISTS idx_detection_vendor ON detection(vendor_id);

CREATE TABLE IF NOT EXISTS detection_evidence (
    detection_id INTEGER NOT NULL REFERENCES detection(id) ON DELETE CASCADE,
    dns_record_id INTEGER NOT NULL REFERENCES dns_record(id) ON DELETE CASCADE,
    PRIMARY KEY (detection_id, dns_record_id)
);

CREATE TABLE IF NOT EXISTS domain_vendor_observation (
    id INTEGER PRIMARY KEY,
    domain_normalized TEXT NOT NULL,
    vendor_id INTEGER NOT NULL REFERENCES vendor(id) ON DELETE CASCADE,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    detection_count INTEGER NOT NULL DEFAULT 1,
    UNIQUE(domain_normalized, vendor_id)
);
CREATE INDEX IF NOT EXISTS idx_dvo_vendor_lastseen ON domain_vendor_observation(vendor_id, last_seen);

CREATE TABLE IF NOT EXISTS domain_vendor_rule_observation (
    id INTEGER PRIMARY KEY,
    domain_normalized TEXT NOT NULL,
    vendor_id INTEGER NOT NULL REFERENCES vendor(id) ON DELETE CASCADE,
    rule_id INTEGER NOT NULL REFERENCES fingerprint_rule(id) ON DELETE CASCADE,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(domain_normalized, vendor_id, rule_id)
);
