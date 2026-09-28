import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

/* One store per server instance, so an embedding process (the Conductore
   companion) can run its own talkbawt next to the deployed one without
   sharing a database or module state. */
export function openStore(dbPath) {
  if (dbPath !== ':memory:') mkdirSync(dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);

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

  // Added after the first release; the deployed database predates them.
  const addColumns = (table, cols) => {
    const have = db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
    for (const [name, type] of cols)
      if (!have.includes(name)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`);
  };
  addColumns('threads', [
    ['creator_hash', 'TEXT'],
    ['revoked_at', 'TEXT'],         // null on threads revoked before retention existed
    ['sign_mode', 'TEXT'],          // null = off | 'optional' | 'required'
    ['owner_sign_key', 'TEXT'],     // HMAC keys; kept raw, like the tokens, to verify with
    ['guest_sign_key', 'TEXT'],
  ]);
  addColumns('messages', [
    ['signed_by', 'TEXT'],          // null = unverified | 'owner' | 'guest'
    ['sig', 'TEXT'],                // the signature, unique per thread, so it cannot be replayed
  ]);
  db.exec(`
    CREATE INDEX IF NOT EXISTS threads_creator ON threads(creator_hash);
    CREATE UNIQUE INDEX IF NOT EXISTS messages_sig ON messages(thread_id, sig) WHERE sig IS NOT NULL;
  `);

  const q = {
    threadByToken: db.prepare(
      `SELECT t.*, k.token AS tok, k.role AS tok_role, k.revoked AS tok_revoked, k.label AS tok_label
         FROM tokens k JOIN threads t ON t.id = k.thread_id
        WHERE k.token = ?`),
    insertThread: db.prepare(
      `INSERT INTO threads (title, mode, created_at, expires_at, pass_hash, pass_salt, max_reads, creator_hash,
                            sign_mode, owner_sign_key, guest_sign_key)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
    tokensFor: db.prepare(`SELECT token, role, label, created_at, revoked FROM tokens WHERE thread_id = ? ORDER BY created_at`),
    messages: db.prepare(
      `SELECT seq, author, role, body, created_at, signed_by FROM messages WHERE thread_id = ? AND seq > ? ORDER BY seq`),
    maxSeq: db.prepare(`SELECT COALESCE(MAX(seq), 0) AS n FROM messages WHERE thread_id = ?`),
    insertToken: db.prepare(
      `INSERT INTO tokens (token, thread_id, role, label, created_at) VALUES (?, ?, ?, ?, ?)`),
    insertMessage: db.prepare(
      `INSERT INTO messages (thread_id, seq, author, role, body, created_at, signed_by, sig) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
    sigSeen: db.prepare(`SELECT 1 AS hit FROM messages WHERE thread_id = ? AND sig = ?`),
    addReader: db.prepare(`INSERT OR IGNORE INTO readers (thread_id, client, first_at) VALUES (?, ?, ?)`),
    knownReader: db.prepare(`SELECT 1 AS hit FROM readers WHERE thread_id = ? AND client = ?`),
    countReaders: db.prepare(`SELECT COUNT(*) AS n FROM readers WHERE thread_id = ?`),
    byCreator: db.prepare(
      `SELECT * FROM threads
        WHERE creator_hash = ? AND (revoked = 0 OR ? = 1) AND expires_at > ?
        ORDER BY created_at DESC LIMIT 100`),
    byCreatorRevoked: db.prepare(
      `SELECT * FROM threads
        WHERE creator_hash = ? AND revoked = 1 AND revoked_at IS NOT NULL
        ORDER BY created_at DESC LIMIT 100`),
    revokeThread: db.prepare(`UPDATE threads SET revoked = 1, revoked_at = ? WHERE id = ?`),
    purgeMessages: db.prepare(`DELETE FROM messages WHERE thread_id = ?`),
    revokeToken: db.prepare(`UPDATE tokens SET revoked = 1 WHERE token = ?`),
    log: db.prepare(
      `INSERT INTO access_log (thread_id, at, action, role, ok, ip, ua, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
    logFor: db.prepare(`SELECT at, action, role, ok, ip, ua, note FROM access_log WHERE thread_id = ? ORDER BY id DESC LIMIT 100`),
    countWrites: db.prepare(`SELECT COUNT(*) AS n FROM access_log WHERE thread_id = ? AND action IN ('created', 'wrote')`),
    // A live thread goes at its expiry. A revoked one is kept past its expiry
    // until its retention window closes, so the owner can still read the log;
    // one revoked before revoked_at existed goes at its expiry as before.
    sweep: db.prepare(
      `DELETE FROM threads
        WHERE (revoked_at IS NULL AND expires_at < ?)
           OR (revoked_at IS NOT NULL AND revoked_at < ?)`),
  };

  const nowISO = () => new Date().toISOString();

  return {
    db,
    nowISO,
    close: () => db.close(),

    findByToken: (token) => q.threadByToken.get(token) ?? null,

    createThread({ title, mode, expiresAt, passHash, passSalt, maxReads, creatorHash, signMode, ownerSignKey, guestSignKey }) {
      const info = q.insertThread.run(title, mode, nowISO(), expiresAt, passHash, passSalt, maxReads,
        creatorHash ?? null, signMode ?? null, ownerSignKey ?? null, guestSignKey ?? null);
      return Number(info.lastInsertRowid);
    },

    addToken: (token, threadId, role, label) => q.insertToken.run(token, threadId, role, label ?? null, nowISO()),
    tokensFor: (threadId) => q.tokensFor.all(threadId),

    addMessage(threadId, { author, role, body, signedBy = null, sig = null }) {
      const seq = Number(q.maxSeq.get(threadId).n) + 1;
      q.insertMessage.run(threadId, seq, author, role, body, nowISO(), signedBy, sig);
      return seq;
    },
    signatureSeen: (threadId, sig) => Boolean(q.sigSeen.get(threadId, sig)),
    messagesSince: (threadId, since) => q.messages.all(threadId, since),
    maxSeq: (threadId) => Number(q.maxSeq.get(threadId).n),

    /* readers */
    recordReader: (threadId, client) => q.addReader.run(threadId, client, nowISO()),
    isKnownReader: (threadId, client) => Boolean(q.knownReader.get(threadId, client)),
    countReaders: (threadId) => Number(q.countReaders.get(threadId).n),

    /* creator index */
    threadsByCreator: (creatorHash, { includeRevoked = false } = {}) => {
      const live = q.byCreator.all(creatorHash, 0, nowISO());
      return includeRevoked ? [...live, ...q.byCreatorRevoked.all(creatorHash)] : live;
    },

    /* Revoking purges the message bodies at once - the content should not
       outlive the link - and keeps the thread row and access log for the
       owner until the retention window closes. */
    revokeThread(threadId) {
      q.revokeThread.run(nowISO(), threadId);
      q.purgeMessages.run(threadId);
    },
    revokeToken: (token) => q.revokeToken.run(token),
    accessLog: (threadId) => q.logFor.all(threadId),
    countWrites: (threadId) => Number(q.countWrites.get(threadId).n),

    log(threadId, action, { role = null, ok = true, ip = null, ua = null, note = null } = {}) {
      q.log.run(threadId, nowISO(), action, role, ok ? 1 : 0, ip, ua ? String(ua).slice(0, 200) : null, note);
    },

    sweepExpired(revokedRetentionMs) {
      const now = Date.now();
      return Number(q.sweep.run(new Date(now).toISOString(), new Date(now - revokedRetentionMs).toISOString()).changes);
    },
  };
}
