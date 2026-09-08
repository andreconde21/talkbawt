import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const DB_PATH = process.env.DB_PATH || '/data/talkbawt.db';

mkdirSync(dirname(DB_PATH), { recursive: true });

export const db = new DatabaseSync(DB_PATH);

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS threads (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    title           TEXT    NOT NULL,
    mode            TEXT    NOT NULL,           -- 'thread' | 'handoff'
    created_at      TEXT    NOT NULL,
    expires_at      TEXT    NOT NULL,
    pass_hash       TEXT,                        -- scrypt hash, null = no passphrase
    pass_salt       TEXT,
    max_reads       INTEGER,                     -- null = unlimited distinct readers
    guest_reads     INTEGER NOT NULL DEFAULT 0,  -- legacy, superseded by the readers table
    revoked         INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS tokens (
    token           TEXT    PRIMARY KEY,
    thread_id       INTEGER NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    role            TEXT    NOT NULL,           -- 'owner' | 'guest'
    label           TEXT,
    created_at      TEXT    NOT NULL,
    revoked         INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS tokens_thread ON tokens(thread_id);

  CREATE TABLE IF NOT EXISTS messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id       INTEGER NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    seq             INTEGER NOT NULL,
    author          TEXT    NOT NULL,
    role            TEXT    NOT NULL,
    body            TEXT    NOT NULL,
    created_at      TEXT    NOT NULL
  );
  CREATE UNIQUE INDEX IF NOT EXISTS messages_seq ON messages(thread_id, seq);

  -- One row per distinct client that has read a thread, so a refresh, or a
  -- browser and an agent on the same machine, does not burn extra reads.
  CREATE TABLE IF NOT EXISTS readers (
    thread_id       INTEGER NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    client          TEXT    NOT NULL,           -- salted hash of ip + user agent
    first_at        TEXT    NOT NULL,
    PRIMARY KEY (thread_id, client)
  );

  CREATE TABLE IF NOT EXISTS access_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id       INTEGER NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    at              TEXT    NOT NULL,
    action          TEXT    NOT NULL,
    role            TEXT,
    ok              INTEGER NOT NULL,
    ip              TEXT,
    ua              TEXT,
    note            TEXT
  );
  CREATE INDEX IF NOT EXISTS access_thread ON access_log(thread_id, id DESC);
`);

// Added after the first release; the deployed database predates it.
const threadCols = db.prepare('PRAGMA table_info(threads)').all().map((c) => c.name);
if (!threadCols.includes('creator_hash')) db.exec('ALTER TABLE threads ADD COLUMN creator_hash TEXT');
db.exec('CREATE INDEX IF NOT EXISTS threads_creator ON threads(creator_hash)');

const q = {
  threadByToken: db.prepare(
    `SELECT t.*, k.token AS tok, k.role AS tok_role, k.revoked AS tok_revoked, k.label AS tok_label
       FROM tokens k JOIN threads t ON t.id = k.thread_id
      WHERE k.token = ?`),
  insertThread: db.prepare(
    `INSERT INTO threads (title, mode, created_at, expires_at, pass_hash, pass_salt, max_reads, creator_hash)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
  tokensFor: db.prepare(`SELECT token, role, label, created_at, revoked FROM tokens WHERE thread_id = ? ORDER BY created_at`),
  messages: db.prepare(`SELECT seq, author, role, body, created_at FROM messages WHERE thread_id = ? AND seq > ? ORDER BY seq`),
  maxSeq: db.prepare(`SELECT COALESCE(MAX(seq), 0) AS n FROM messages WHERE thread_id = ?`),
  insertToken: db.prepare(
    `INSERT INTO tokens (token, thread_id, role, label, created_at) VALUES (?, ?, ?, ?, ?)`),
  insertMessage: db.prepare(
    `INSERT INTO messages (thread_id, seq, author, role, body, created_at) VALUES (?, ?, ?, ?, ?, ?)`),
  addReader: db.prepare(`INSERT OR IGNORE INTO readers (thread_id, client, first_at) VALUES (?, ?, ?)`),
  knownReader: db.prepare(`SELECT 1 AS hit FROM readers WHERE thread_id = ? AND client = ?`),
  countReaders: db.prepare(`SELECT COUNT(*) AS n FROM readers WHERE thread_id = ?`),
  byCreator: db.prepare(
    `SELECT * FROM threads
      WHERE creator_hash = ? AND revoked = 0 AND expires_at > ?
      ORDER BY created_at DESC LIMIT 100`),
  revokeThread: db.prepare(`UPDATE threads SET revoked = 1 WHERE id = ?`),
  revokeToken: db.prepare(`UPDATE tokens SET revoked = 1 WHERE token = ?`),
  log: db.prepare(
    `INSERT INTO access_log (thread_id, at, action, role, ok, ip, ua, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
  logFor: db.prepare(`SELECT at, action, role, ok, ip, ua, note FROM access_log WHERE thread_id = ? ORDER BY id DESC LIMIT 100`),
  sweep: db.prepare(`DELETE FROM threads WHERE expires_at < ?`),
};

export const nowISO = () => new Date().toISOString();

export function findByToken(token) {
  return q.threadByToken.get(token) ?? null;
}

export function createThread({ title, mode, expiresAt, passHash, passSalt, maxReads, creatorHash }) {
  const info = q.insertThread.run(title, mode, nowISO(), expiresAt, passHash, passSalt, maxReads, creatorHash ?? null);
  return Number(info.lastInsertRowid);
}

export function addToken(token, threadId, role, label) {
  q.insertToken.run(token, threadId, role, label ?? null, nowISO());
}

export const tokensFor = (threadId) => q.tokensFor.all(threadId);

export function addMessage(threadId, { author, role, body }) {
  const seq = Number(q.maxSeq.get(threadId).n) + 1;
  q.insertMessage.run(threadId, seq, author, role, body, nowISO());
  return seq;
}

export const messagesSince = (threadId, since) => q.messages.all(threadId, since);
export const maxSeq = (threadId) => Number(q.maxSeq.get(threadId).n);

/* readers ------------------------------------------------------------- */

export const recordReader = (threadId, client) => q.addReader.run(threadId, client, nowISO());
export const isKnownReader = (threadId, client) => Boolean(q.knownReader.get(threadId, client));
export const countReaders = (threadId) => Number(q.countReaders.get(threadId).n);

/* creator index ------------------------------------------------------- */

export const threadsByCreator = (creatorHash) => q.byCreator.all(creatorHash, nowISO());

/* misc ---------------------------------------------------------------- */

export const revokeThread = (threadId) => q.revokeThread.run(threadId);
export const revokeToken = (token) => q.revokeToken.run(token);
export const accessLog = (threadId) => q.logFor.all(threadId);

export function log(threadId, action, { role = null, ok = true, ip = null, ua = null, note = null } = {}) {
  q.log.run(threadId, nowISO(), action, role, ok ? 1 : 0, ip, ua ? String(ua).slice(0, 200) : null, note);
}

export function sweepExpired() {
  return Number(q.sweep.run(nowISO()).changes);
}
