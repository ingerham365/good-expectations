-- Good Expectations CRM — D1 schema
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS contacts (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  company     TEXT DEFAULT '',
  title       TEXT DEFAULT '',
  email       TEXT DEFAULT '',
  phone       TEXT DEFAULT '',
  source      TEXT DEFAULT '',
  tags        TEXT DEFAULT '[]',      -- JSON array of strings
  notes       TEXT DEFAULT '',
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_contacts_email ON contacts(lower(email));
CREATE INDEX IF NOT EXISTS idx_contacts_phone ON contacts(phone);

CREATE TABLE IF NOT EXISTS deals (
  id           TEXT PRIMARY KEY,
  title        TEXT NOT NULL,
  contact_id   TEXT REFERENCES contacts(id) ON DELETE SET NULL,
  stage        TEXT NOT NULL DEFAULT 'lead',
  value        REAL NOT NULL DEFAULT 0,
  probability  INTEGER,                -- null = use stage default
  close_date   TEXT DEFAULT '',
  notes        TEXT DEFAULT '',
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  stage_changed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_deals_contact ON deals(contact_id);

CREATE TABLE IF NOT EXISTS tasks (
  id          TEXT PRIMARY KEY,
  title       TEXT NOT NULL,
  due_date    TEXT DEFAULT '',
  priority    TEXT DEFAULT 'normal',  -- low | normal | high
  recurrence  TEXT DEFAULT 'none',    -- none | daily | weekly | biweekly | monthly
  contact_id  TEXT REFERENCES contacts(id) ON DELETE SET NULL,
  deal_id     TEXT REFERENCES deals(id) ON DELETE SET NULL,
  done        INTEGER NOT NULL DEFAULT 0,
  done_at     TEXT DEFAULT '',
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activities (
  id          TEXT PRIMARY KEY,
  type        TEXT NOT NULL,          -- note | call | email | meeting | system
  body        TEXT NOT NULL,
  contact_id  TEXT REFERENCES contacts(id) ON DELETE CASCADE,
  deal_id     TEXT REFERENCES deals(id) ON DELETE SET NULL,
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_activities_contact ON activities(contact_id);

CREATE TABLE IF NOT EXISTS login_attempts (
  ip          TEXT NOT NULL,
  at          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(ip, at);
