PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS capsules (
  id TEXT PRIMARY KEY,
  access_hash TEXT NOT NULL UNIQUE,
  owner_hash TEXT NOT NULL,
  envelope TEXT NOT NULL,
  payload_ciphertext TEXT NOT NULL,
  metadata_ciphertext TEXT NOT NULL,
  mode TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  one_time INTEGER NOT NULL DEFAULT 0,
  consumed_at INTEGER,
  expires_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  capsule_id TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending',
  device TEXT NOT NULL,
  os TEXT NOT NULL,
  browser TEXT NOT NULL,
  region TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(capsule_id) REFERENCES capsules(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  capsule_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  decision TEXT NOT NULL DEFAULT 'pending',
  actor TEXT,
  created_at INTEGER NOT NULL,
  decided_at INTEGER,
  FOREIGN KEY(capsule_id) REFERENCES capsules(id) ON DELETE CASCADE,
  FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  capsule_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  session_id TEXT,
  detail TEXT NOT NULL,
  event_hash TEXT NOT NULL,
  previous_hash TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(capsule_id) REFERENCES capsules(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_capsules_access_hash ON capsules(access_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_capsule ON sessions(capsule_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_approvals_capsule ON approvals(capsule_id, decision);
CREATE INDEX IF NOT EXISTS idx_audit_capsule ON audit_events(capsule_id, id);
