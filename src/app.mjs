import { createServer } from 'node:http';
import { openStore } from './db.mjs';
import {
  newToken, hashPass, checkPass, parseTTL, scanForSecrets, makeRateLimiter,
  isPreviewBot, clientHash, newCreatorKey, hashKey,
  newSignKey, parseSignature, verifySignature, SIGNATURE_WINDOW_S,
} from './guards.mjs';
import {
  renderThread, renderMarkdown, renderHome, renderRevoked, SECURITY_NOTICE, REPLY_HELP,
} from './render.mjs';

const MAX_BODY = 256 * 1024;          // per request
const MAX_TEXT = 200 * 1024;          // per message
const MAX_MESSAGES = 500;             // per thread
const DEFAULT_TTL = 1 * 86400e3;
const MAX_WAIT = 50;                  // seconds a long poll may be held open
const MAX_WAITERS = 100;              // concurrent held requests, watches included
const MAX_WATCHED = 50;               // threads per POST /api/watch
const WATCH_MESSAGES = 100;           // new messages returned per thread per watch answer
const POLL_MS = 500;
const REVOKED_RETENTION = 7 * 86400e3;
const TOKEN_RE = /^[A-Za-z0-9_]{10,80}$/;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const SEC_HEADERS = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-robots-tag': 'noindex, nofollow',
  'cache-control': 'no-store',
};

function send(res, code, type, payload, extra = {}) {
  res.writeHead(code, { 'content-type': type, ...SEC_HEADERS, ...extra });
  res.end(payload);
}
const json = (res, code, obj, extra) =>
  send(res, code, 'application/json; charset=utf-8', JSON.stringify(obj, null, 2), extra);
const html = (res, code, body, extra = {}) =>
  send(res, code, 'text/html; charset=utf-8', body, {
    'content-security-policy':
      "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    ...extra,
  });
const limited = (res, rl, message) =>
  json(res, 429, { error: 'rate_limited', message }, { 'retry-after': String(rl.retryAfter ?? 60) });

/* The raw text is kept next to the parsed JSON: a signature covers the bytes
   the client sent, not our re-serialisation of them. */
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(Object.assign(new Error('body too large'), { code: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw.trim()) return resolve({ body: {}, raw });
      try { resolve({ body: JSON.parse(raw), raw }); }
      catch { reject(Object.assign(new Error('body must be valid JSON'), { code: 400 })); }
    });
    req.on('error', reject);
  });
}

const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const wantsHTML = (req, fmt) =>
  fmt === 'html' || (!fmt && (req.headers.accept ?? '').includes('text/html'));
// Not req.destroyed: a request whose body has been read is destroyed by then,
// though its caller is still waiting for the answer.
const callerGone = (res) => res.writableEnded || res.destroyed || Boolean(res.socket?.destroyed);
const isExpired = (row) => new Date(row.expires_at) < new Date();

/**
 * Builds a talkbawt server without starting it.
 *
 *   dbPath             SQLite file (created with its directory), or ':memory:'. Required.
 *   baseUrl            Public origin used in the links it hands out. Unset: taken from the request.
 *   trustProxy         Honour X-Forwarded-For/-Proto/-Host. Only behind a proxy that sets them;
 *                      otherwise any client can spoof its address past the rate limits. Default false.
 *   revokedRetentionMs How long a revoked thread's access log stays readable. Default 7 days.
 *   logger             { log, error }. Default console.
 *
 * Returns { server, handler, store, listen(port?, host?), close() }.
 */
export function createTalkbawt({
  dbPath, baseUrl = null, trustProxy = false,
  revokedRetentionMs = REVOKED_RETENTION, logger = console,
} = {}) {
  if (!dbPath) throw new Error('createTalkbawt: dbPath is required');
  const store = openStore(dbPath);
  const rateLimit = makeRateLimiter();
  let waiters = 0;
  let closing = false;

  const fwd = (req, name) => (trustProxy ? req.headers[name] : undefined);
  const clientIP = (req) =>
    (fwd(req, 'x-forwarded-for') ?? '').toString().split(',')[0].trim() ||
    req.socket.remoteAddress || 'unknown';

  const baseURL = (req) => {
    if (baseUrl) return baseUrl.replace(/\/$/, '');
    const proto = (fwd(req, 'x-forwarded-proto') ?? 'http').toString().split(',')[0];
    const host = (fwd(req, 'x-forwarded-host') ?? req.headers.host ?? 'localhost').toString();
    return `${proto}://${host}`;
  };

  const retainedUntil = (thread) => (thread.revoked_at
    ? new Date(new Date(thread.revoked_at).getTime() + revokedRetentionMs).toISOString()
    : thread.expires_at);

  const shareTokenOf = (threadId) =>
    store.tokensFor(threadId).find((t) => t.role === 'guest' && !t.revoked)?.token ?? null;

  const readsLeft = (thread) =>
    (thread.max_reads == null ? null : Math.max(0, thread.max_reads - store.countReaders(thread.id)));

  const outMessage = (m) => ({
    seq: m.seq, from: m.author, at: m.created_at,
    verified: Boolean(m.signed_by), signed_by: m.signed_by ?? null,
    untrusted_content: m.body,
  });

  /* ---------- access resolution ---------- */

  // `meta` resolves for GET /t/{token}/meta and HEAD: it never counts a read,
  // answers even once the read limit is reached, and without a passphrase it
  // resolves too, but as passOk: false, so the caller withholds the content.
  function resolveAccess(req, token, url, { meta = false } = {}) {
    const row = store.findByToken(token);
    if (!row) return { error: [404, { error: 'not_found', message: 'No such thread. The link may have been revoked or it may have expired.' }] };

    const ip = clientIP(req);
    const ua = req.headers['user-agent'] ?? '';
    const ctx = { ip, ua, bot: isPreviewBot(ua), client: clientHash(ip, ua) };

    const deny = (code, body, note) => {
      store.log(row.id, 'denied', { role: row.tok_role, ok: false, ip, ua, note });
      return { error: [code, body] };
    };

    if (row.revoked || row.tok_revoked) {
      // The owner keeps a read-only view of who had the link, until retention ends.
      if (row.tok_role === 'owner' && row.revoked_at) return { thread: row, role: 'owner', ctx, revoked: true };
      return deny(410, { error: 'revoked', message: 'This link was revoked by its owner.' }, 'revoked');
    }
    if (isExpired(row)) return deny(410, { error: 'expired', message: `This thread expired on ${row.expires_at}.` }, 'expired');

    let passOk = true;
    if (row.tok_role === 'guest') {
      if (row.pass_hash) {
        const pass = (req.headers['x-talkbawt-passphrase'] ?? url.searchParams.get('p') ?? '').toString();
        if (meta && !pass) passOk = false;
        else if (!checkPass(pass, row.pass_hash, row.pass_salt)) {
          const rl = rateLimit(`badpass:${ip}`, 15, 3600e3);
          if (!rl.ok) return deny(429, { error: 'too_many_attempts', message: 'Too many failed passphrase attempts.' }, 'passphrase lockout');
          return deny(401, {
            error: 'passphrase_required',
            message: 'This thread is passphrase-protected. Ask the person who sent you the link for the passphrase, then retry with header `X-Talkbawt-Passphrase: <passphrase>`.',
          }, 'bad passphrase');
        }
      }
      // Burn-after-reading counts distinct readers rather than requests, and a
      // link preview never counts: an unfurler must not be able to consume the
      // recipient's only read before they have clicked anything.
      if (!meta && row.max_reads != null && !ctx.bot
          && !store.isKnownReader(row.id, ctx.client)
          && store.countReaders(row.id) >= row.max_reads) {
        return deny(410, { error: 'read_limit_reached', message: 'This link has already been opened by the maximum number of readers.' }, 'read limit');
      }
    }

    return { thread: row, role: row.tok_role, ctx, passOk };
  }

  /* ---------- routes ---------- */

  async function createThread(req, res) {
    const ip = clientIP(req);
    const rl = rateLimit(`create:${ip}`, 120, 3600e3);
    if (!rl.ok) return limited(res, rl, 'Too many threads created from this address. Try again later.');

    const { body: b } = await readBody(req);
    const title = str(b.title, 200) || 'Untitled handoff';
    const mode = b.mode === 'handoff' ? 'handoff' : 'thread';
    const from = str(b.from, 120) || 'unidentified agent';
    const text = typeof b.text === 'string' ? b.text : (typeof b.body === 'string' ? b.body : '');

    if (!text.trim()) return json(res, 400, { error: 'missing_text', message: 'Provide `text`: the handoff content itself.' });
    if (text.length > MAX_TEXT) return json(res, 413, { error: 'too_large', message: `Content exceeds ${MAX_TEXT} bytes.` });

    const ttl = parseTTL(b.expires_in, DEFAULT_TTL);
    if (ttl === null) return json(res, 400, { error: 'bad_expires_in', message: 'Use a duration like "30m", "12h", "1d" or "7d" (7 days max).' });

    let maxReads = null;
    if (b.max_reads != null) {
      maxReads = Number(b.max_reads);
      if (!Number.isInteger(maxReads) || maxReads < 1 || maxReads > 1000)
        return json(res, 400, { error: 'bad_max_reads', message: '`max_reads` must be an integer between 1 and 1000.' });
    }

    let pass = null;
    if (b.passphrase != null) {
      const p = String(b.passphrase);
      if (p.length < 6) return json(res, 400, { error: 'weak_passphrase', message: 'A passphrase must be at least 6 characters. Send it to the other person over a different channel than the link.' });
      pass = hashPass(p);
    }

    let signMode = null;
    if (b.signing === true || b.signing === 'optional') signMode = 'optional';
    else if (b.signing === 'required') signMode = 'required';
    else if (b.signing != null && b.signing !== false)
      return json(res, 400, { error: 'bad_signing', message: '`signing` is true, "optional" or "required".' });

    const findings = scanForSecrets(text);
    if (findings.length && b.override_secret_scan !== true)
      return json(res, 422, {
        error: 'possible_credentials',
        message: 'This content looks like it contains live credentials. Anyone with the share link could read them. Remove the secret and tell the other side where to fetch it from, or resend with "override_secret_scan": true if this is a false positive.',
        findings,
      });

    // An optional creator key groups the threads one person made, so losing an
    // owner_url does not mean losing the thread. Generated server-side, so it is
    // never weak, returned once, and stored only as a hash.
    const suppliedKey = str(b.creator_key, 200) || str(req.headers['x-talkbawt-key'], 200);
    const issueKey = !suppliedKey && b.remember === true;
    const creatorKey = suppliedKey || (issueKey ? newCreatorKey() : null);

    const ownerSignKey = signMode ? newSignKey('owner') : null;
    const guestSignKey = signMode ? newSignKey('guest') : null;
    const expiresAt = new Date(Date.now() + ttl).toISOString();

    const id = store.createThread({
      title, mode, expiresAt,
      passHash: pass?.hash ?? null, passSalt: pass?.salt ?? null, maxReads,
      creatorHash: creatorKey ? hashKey(creatorKey) : null,
      signMode, ownerSignKey, guestSignKey,
    });
    const guest = newToken('g');
    const owner = newToken('o');
    store.addToken(guest, id, 'guest', 'shared link');
    store.addToken(owner, id, 'owner', 'creator');
    // The keys are issued in this very response, so the first message is by
    // definition the owner key holder's.
    store.addMessage(id, { author: from, role: 'owner', body: text, signedBy: signMode ? 'owner' : null });
    store.log(id, 'created', { role: 'owner', ip, ua: req.headers['user-agent'], note: findings.length ? 'secret scan overridden' : null });

    const base = baseURL(req);
    const shareURL = `${base}/t/${guest}`;
    const body = {
      ok: true,
      mode,
      title,
      expires_at: expiresAt,
      share_url: shareURL,
      owner_url: `${base}/t/${owner}`,
      passphrase_required: Boolean(pass),
      max_reads: maxReads,
      give_the_other_person: `Handoff for you: ${shareURL} — open it, or paste the URL to your ` +
        `coding agent and ask it to fetch it.${pass ? ' It is passphrase-protected; I will send the passphrase separately.' : ''}`,
      keep_private: 'owner_url is yours alone: it revokes the link and shows who has read it. Never share it.',
      next_steps: mode === 'thread'
        ? { watch_for_replies: `${shareURL}?since=1&wait=30&format=json`, watch_many: `POST ${base}/api/watch`, revoke: `POST ${base}/t/${owner}/revoke` }
        : { revoke: `POST ${base}/t/${owner}/revoke` },
    };
    if (signMode) {
      body.signing = {
        mode: signMode,
        owner_key: ownerSignKey,
        guest_key: guestSignKey,
        how: 'Sign a post with header `X-Talkbawt-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(key, "<t>.<exact request body>")>`. ' +
          'Signed posts are shown as verified with the signer\'s role; unsigned ones as unverified' +
          (signMode === 'required' ? ', and on this thread they are refused.' : '.'),
        keep_private: 'Keep owner_key. Give guest_key to the other person over a different channel than the link, ' +
          'like a passphrase. Both are shown once.',
      };
    }
    if (creatorKey) body.your_threads = `${base}/api/mine`;
    if (issueKey) {
      body.creator_key = creatorKey;
      body.keep_creator_key = 'Save this key. Send it as `X-Talkbawt-Key` when you create a thread ' +
        'to add it to your list, and to GET /api/mine to list the threads you still have open. ' +
        'It is shown once and stored only as a hash, so it cannot be recovered.';
    }
    return json(res, 201, body);
  }

  function listMine(req, res, url) {
    const rl = rateLimit(`mine:${clientIP(req)}`, 60, 3600e3);
    if (!rl.ok) return limited(res, rl, 'Too many listings from this address. Try again later.');

    const key = str(req.headers['x-talkbawt-key'], 200) || str(url.searchParams.get('key'), 200);
    if (!key) return json(res, 401, {
      error: 'key_required',
      message: 'Send your creator key as `X-Talkbawt-Key`. You get one by creating a thread with "remember": true.',
    });

    const includeRevoked = url.searchParams.get('include') === 'revoked';
    const base = baseURL(req);
    const rows = store.threadsByCreator(hashKey(key), { includeRevoked });
    return json(res, 200, {
      count: rows.length,
      note: includeRevoked
        ? 'Threads you created with this key: live ones, and revoked ones whose access log is still retained.'
        : 'Live threads you created with this key. Expired and revoked threads are not listed; add ?include=revoked for revoked ones still in retention.',
      threads: rows.map((t) => {
        const owner = store.tokensFor(t.id).find((k) => k.role === 'owner');
        const guest = t.revoked ? null : shareTokenOf(t.id);
        return {
          title: t.title,
          mode: t.mode,
          state: t.revoked ? 'revoked' : 'live',
          created_at: t.created_at,
          expires_at: t.expires_at,
          ...(t.revoked ? { revoked_at: t.revoked_at, retained_until: retainedUntil(t) } : {}),
          messages: store.maxSeq(t.id),
          distinct_readers: store.countReaders(t.id),
          max_reads: t.max_reads,
          passphrase_required: Boolean(t.pass_hash),
          signing: t.sign_mode ?? 'off',
          share_url: guest ? `${base}/t/${guest}` : null,
          owner_url: owner ? `${base}/t/${owner.token}` : null,
        };
      }),
    });
  }

  /* After a revoke the owner URL answers 410 like every other client, so
     existing pollers stop, but the body carries what the owner still needs:
     who had the link, and when. The messages are already gone. */
  function showRevoked(req, res, url, access) {
    const { thread, ctx } = access;
    store.log(thread.id, 'read', { role: 'owner', ip: ctx.ip, ua: ctx.ua, note: 'revoked view' });
    const view = {
      thread, log: store.accessLog(thread.id), readers: store.countReaders(thread.id),
      writes: store.countWrites(thread.id), retainedUntil: retainedUntil(thread),
    };
    if (wantsHTML(req, url.searchParams.get('format'))) return html(res, 410, renderRevoked(view));
    return json(res, 410, {
      error: 'revoked',
      message: 'You revoked this thread. The share link no longer resolves and the messages were deleted. ' +
        `This owner view keeps the access log until ${view.retainedUntil}, then the thread is gone.`,
      thread: {
        title: thread.title, mode: thread.mode, state: 'revoked',
        created_at: thread.created_at, expires_at: thread.expires_at,
        revoked_at: thread.revoked_at, retained_until: view.retainedUntil,
      },
      owner: {
        distinct_readers: view.readers,
        max_reads: thread.max_reads,
        messages_written: view.writes,
        access_log: view.log,
      },
    });
  }

  async function showThread(req, res, url, access, token) {
    const { thread, role, ctx } = access;
    if (access.revoked) return showRevoked(req, res, url, access);
    const since = Math.max(0, Number(url.searchParams.get('since') ?? 0) || 0);
    const fmt = url.searchParams.get('format');
    const base = baseURL(req);

    // Long poll: hold the request open until something new lands, so an agent
    // watching for a reply makes one call instead of forty.
    const wait = Math.min(Math.max(Number(url.searchParams.get('wait') ?? 0) || 0, 0), MAX_WAIT);
    if (wait > 0 && waiters < MAX_WAITERS && store.maxSeq(thread.id) <= since) {
      waiters++;
      try {
        const deadline = Date.now() + wait * 1000;
        while (Date.now() < deadline) {
          await sleep(POLL_MS);
          if (closing || callerGone(res)) return;   // caller gave up
          if (store.maxSeq(thread.id) > since) break;
        }
      } finally { waiters--; }
      const fresh = store.findByToken(token);
      if (!fresh || fresh.revoked || fresh.tok_revoked)
        return json(res, 410, { error: 'revoked', message: 'This link was revoked while you were waiting.' });
    }

    const messages = store.messagesSince(thread.id, since);

    if (role === 'guest' && !ctx.bot) store.recordReader(thread.id, ctx.client);
    store.log(thread.id, ctx.bot ? 'preview' : 'read', {
      role, ip: ctx.ip, ua: ctx.ua, note: ctx.bot ? 'link preview, not counted as a read' : null,
    });

    // A poller holding the current version gets 304 and no body.
    const etag = `W/"${thread.id}-${store.maxSeq(thread.id)}-${since}-${fmt ?? 'auto'}"`;
    if ((req.headers['if-none-match'] ?? '') === etag)
      return send(res, 304, 'text/plain; charset=utf-8', '', { etag });

    const accessLog = role === 'owner' ? store.accessLog(thread.id) : null;
    if (wantsHTML(req, fmt))
      return html(res, 200, renderThread({ thread, messages, base, token, role, accessLog }), { etag });
    if (fmt === 'md' || fmt === 'markdown')
      return send(res, 200, 'text/markdown; charset=utf-8', renderMarkdown({ thread, messages, base, token }), { etag });

    const payload = {
      security_notice: SECURITY_NOTICE,
      thread: {
        title: thread.title,
        mode: thread.mode,
        created_at: thread.created_at,
        expires_at: thread.expires_at,
        message_count: messages.length,
        max_reads: thread.max_reads,
        reads_remaining: readsLeft(thread),
        signing: thread.sign_mode ?? 'off',
        your_role: role,
      },
      messages: messages.map(outMessage),
      how_to_reply: REPLY_HELP(base, token, thread.mode, thread.sign_mode),
    };
    if (role === 'owner') {
      const share = shareTokenOf(thread.id);
      payload.owner = {
        share_url: share ? `${base}/t/${share}` : '(revoked)',
        distinct_readers: store.countReaders(thread.id),
        max_reads: thread.max_reads,
        revoke: `POST ${base}/t/${token}/revoke`,
        access_log: accessLog,
      };
    }
    return json(res, 200, payload, { etag });
  }

  /* What a guest can learn before spending a read: whether the link will
     admit them, and how many reads are left. Never counts as a read; the
     title and message count need the passphrase when there is one. */
  function showMeta(req, res, access, head) {
    const { thread, role, ctx, passOk } = access;
    store.log(thread.id, 'checked', { role, ip: ctx.ip, ua: ctx.ua, note: 'metadata, not counted as a read' });
    const left = readsLeft(thread);
    const counted = role === 'guest' && store.isKnownReader(thread.id, ctx.client);
    const admits = role === 'owner' || left == null || counted || left > 0;
    const meta = {
      mode: thread.mode,
      expires_at: thread.expires_at,
      passphrase_required: Boolean(thread.pass_hash),
      max_reads: thread.max_reads,
      reads_remaining: left,
      you_are_already_counted: counted,
      a_read_would_be_admitted: admits,
      a_read_would_use_one_up: role === 'guest' && thread.max_reads != null && !counted && !ctx.bot,
      signing: thread.sign_mode ?? 'off',
      your_role: role,
      ...(passOk ? { title: thread.title, message_count: store.maxSeq(thread.id) } : {}),
      note: 'This check is free: it is not counted as a read. A read from a browser and one from an agent are two distinct readers.',
    };
    const headers = {
      'x-talkbawt-mode': thread.mode,
      'x-talkbawt-expires-at': thread.expires_at,
      'x-talkbawt-passphrase-required': String(Boolean(thread.pass_hash)),
      'x-talkbawt-max-reads': thread.max_reads == null ? 'unlimited' : String(thread.max_reads),
      'x-talkbawt-reads-remaining': left == null ? 'unlimited' : String(left),
      'x-talkbawt-admits-you': String(admits),
    };
    if (head) return send(res, 200, 'application/json; charset=utf-8', '', headers);
    return json(res, 200, meta, headers);
  }

  async function postMessage(req, res, access, token) {
    const { thread, role, ctx } = access;
    if (access.revoked) return json(res, 410, { error: 'revoked', message: 'This thread was revoked; it takes no more messages.' });
    if (thread.mode === 'handoff')
      return json(res, 409, { error: 'read_only', message: 'This is a one-shot handoff, not a thread. It cannot be replied to.' });
    const rl = rateLimit(`post:${token}`, 60, 3600e3);
    if (!rl.ok) return limited(res, rl, 'Too many messages posted to this thread in the last hour.');
    if (store.maxSeq(thread.id) >= MAX_MESSAGES)
      return json(res, 409, { error: 'thread_full', message: `A thread holds at most ${MAX_MESSAGES} messages.` });

    const { body: b, raw } = await readBody(req);

    // Signed `from`: optional, per thread. A bad signature is an error rather
    // than a silent downgrade to unverified, so a signing client notices.
    let signedBy = null, sig = null;
    const sigHeader = req.headers['x-talkbawt-signature'];
    if (sigHeader) {
      if (!thread.sign_mode)
        return json(res, 400, { error: 'signing_not_enabled', message: 'This thread was created without `signing`; post without X-Talkbawt-Signature.' });
      const parsed = parseSignature(sigHeader);
      if (!parsed)
        return json(res, 400, { error: 'bad_signature', message: 'X-Talkbawt-Signature must be `t=<unix seconds>,v1=<64 hex chars>`.' });
      if (Math.abs(Date.now() / 1000 - parsed.t) > SIGNATURE_WINDOW_S)
        return json(res, 401, { error: 'signature_expired', message: `The signature timestamp is more than ${SIGNATURE_WINDOW_S}s from the server clock. Sign again with the current time.` });
      signedBy = verifySignature(parsed, raw, { owner: thread.owner_sign_key, guest: thread.guest_sign_key });
      if (!signedBy) {
        store.log(thread.id, 'blocked', { role, ok: false, note: 'bad signature', ...ctx });
        return json(res, 401, { error: 'bad_signature', message: 'The signature does not match this thread\'s keys and the exact request body.' });
      }
      sig = parsed.v1;
      if (store.signatureSeen(thread.id, sig))
        return json(res, 409, { error: 'replayed_signature', message: 'This signed message was already posted.' });
    } else if (thread.sign_mode === 'required') {
      return json(res, 401, { error: 'signature_required', message: 'This thread only accepts signed messages. Sign with your participant key (X-Talkbawt-Signature).' });
    }

    const from = str(b.from, 120) || `unidentified ${role}`;
    const text = typeof b.text === 'string' ? b.text : (typeof b.body === 'string' ? b.body : '');
    if (!text.trim()) return json(res, 400, { error: 'missing_text', message: 'Provide `text`.' });
    if (text.length > MAX_TEXT) return json(res, 413, { error: 'too_large', message: `Message exceeds ${MAX_TEXT} bytes.` });

    const findings = scanForSecrets(text);
    if (findings.length && b.override_secret_scan !== true) {
      store.log(thread.id, 'blocked', { role, ok: false, note: 'secret scan', ...ctx });
      return json(res, 422, {
        error: 'possible_credentials',
        message: 'This message looks like it contains live credentials, and anyone with the link can read this thread. Remove the secret, or resend with "override_secret_scan": true if it is a false positive.',
        findings,
      });
    }

    const seq = store.addMessage(thread.id, { author: from, role, body: text, signedBy, sig });
    store.log(thread.id, 'wrote', { role, note: `#${seq}${signedBy ? `, signed by ${signedBy} key` : ''}`, ...ctx });
    return json(res, 201, {
      ok: true, seq, verified: Boolean(signedBy), signed_by: signedBy,
      poll_for_replies: `${baseURL(req)}/t/${token}?since=${seq}&format=json`,
    });
  }

  function revoke(req, res, access) {
    const { thread, role, ctx } = access;
    if (role !== 'owner')
      return json(res, 403, { error: 'owner_only', message: 'Only the owner_url can revoke this thread.' });
    if (access.revoked)
      return json(res, 200, { ok: true, already_revoked: true, revoked_at: thread.revoked_at, retained_until: retainedUntil(thread) });
    store.revokeThread(thread.id);
    store.log(thread.id, 'revoked', { role, ...ctx });
    const until = retainedUntil(store.findByToken(thread.tok));
    return json(res, 200, {
      ok: true,
      message: 'Revoked. The share link no longer resolves and the messages were deleted. ' +
        `This owner URL still shows the access log until ${until}.`,
      retained_until: until,
    });
  }

  /* ---------- watching many threads ----------
     POST, so owner tokens travel in the body and never land in an access log
     or a proxy's request line. One held request covers up to MAX_WATCHED
     threads and takes one waiter slot. */

  function watchSnapshot(entry) {
    const row = store.findByToken(entry.token);
    if (!row) return { state: 'not_found' };
    if (row.tok_role !== 'owner') return { state: 'owner_only' };
    const base = { thread: row, title: row.title, mode: row.mode, expires_at: row.expires_at };
    if (row.revoked) return { ...base, state: 'revoked', revoked_at: row.revoked_at, retained_until: retainedUntil(row) };
    if (isExpired(row)) return { ...base, state: 'expired' };
    return { ...base, state: 'live', last_seq: store.maxSeq(row.id), distinct_readers: store.countReaders(row.id) };
  }

  const watchChanged = (entry, s) => s.state !== 'live'
    || s.last_seq > entry.since
    || (entry.readers != null && s.distinct_readers > entry.readers);

  async function watch(req, res) {
    const ip = clientIP(req);
    const rl = rateLimit(`watch:${ip}`, 720, 3600e3);
    if (!rl.ok) return limited(res, rl, 'Too many watch requests from this address. Hold each one open with `wait` instead.');

    const { body: b } = await readBody(req);
    const list = Array.isArray(b.threads) ? b.threads : null;
    if (!list || list.length === 0 || list.length > MAX_WATCHED)
      return json(res, 400, { error: 'bad_threads', message: `Send "threads": [{"token": "o_…", "since": <last seq>, "readers": <last distinct_readers>?, "id": <your label>?}], 1 to ${MAX_WATCHED} entries.` });
    const entries = [];
    for (const e of list) {
      const token = typeof e?.token === 'string' ? e.token.replace(/^.*\/t\//, '') : '';
      if (!TOKEN_RE.test(token))
        return json(res, 400, { error: 'bad_token', message: 'Each entry needs `token`: an owner token (o_…) or owner URL.' });
      entries.push({
        id: e.id ?? null,
        token,
        since: Math.max(0, Number(e.since) || 0),
        readers: e.readers == null ? null : Math.max(0, Number(e.readers) || 0),
      });
    }

    const wait = Math.min(Math.max(Number(b.wait) || 0, 0), MAX_WAIT);
    let snaps = entries.map(watchSnapshot);
    if (wait > 0 && waiters < MAX_WAITERS && !entries.some((e, i) => watchChanged(e, snaps[i]))) {
      waiters++;
      try {
        const deadline = Date.now() + wait * 1000;
        while (Date.now() < deadline) {
          await sleep(POLL_MS);
          if (closing || callerGone(res)) return;
          snaps = entries.map(watchSnapshot);
          if (entries.some((e, i) => watchChanged(e, snaps[i]))) break;
        }
      } finally { waiters--; }
    }

    const ua = req.headers['user-agent'] ?? '';
    const threads = entries.map((e, i) => {
      const { thread, ...s } = snaps[i];
      const out = { id: e.id, changed: watchChanged(e, snaps[i]), ...s };
      if (s.state === 'live') {
        out.readers_changed = e.readers != null && s.distinct_readers > e.readers;
        if (s.last_seq > e.since) {
          const msgs = store.messagesSince(thread.id, e.since);
          out.new_messages = msgs.slice(0, WATCH_MESSAGES).map(outMessage);
          out.more = msgs.length > WATCH_MESSAGES;
          store.log(thread.id, 'read', { role: 'owner', ip, ua, note: 'via watch' });
        } else out.new_messages = [];
      }
      return out;
    });
    return json(res, 200, {
      security_notice: SECURITY_NOTICE,
      changed: threads.filter((t) => t.changed).length,
      threads,
      next: 'Send the same list back with `since` set to each last_seq and `readers` to each distinct_readers. ' +
        'Drop entries whose state is not "live".',
    });
  }

  /* ---------- dispatch ---------- */

  async function handler(req, res) {
    const url = new URL(req.url, 'http://x');
    const path = url.pathname.replace(/\/+$/, '') || '/';

    try {
      const rl = rateLimit(`ip:${clientIP(req)}`, 240, 60e3);
      if (!rl.ok) return limited(res, rl, 'Slow down.');

      if (path === '/healthz') return json(res, 200, { ok: true });
      if (path === '/robots.txt') return send(res, 200, 'text/plain', 'User-agent: *\nDisallow: /\n');
      if (path === '/' && req.method === 'GET') return html(res, 200, renderHome(baseURL(req)));
      if (path === '/api/threads' && req.method === 'POST') return await createThread(req, res);
      if (path === '/api/mine' && req.method === 'GET') return listMine(req, res, url);
      if (path === '/api/watch' && req.method === 'POST') return await watch(req, res);

      const m = path.match(/^\/t\/([A-Za-z0-9_]{10,80})(\/messages|\/revoke|\/meta)?$/);
      if (m) {
        const [, token, sub] = m;
        const isMeta = sub === '/meta' || (!sub && req.method === 'HEAD');
        const access = resolveAccess(req, token, url, { meta: isMeta });
        if (access.error) {
          const [code, body] = access.error;
          if (wantsHTML(req, url.searchParams.get('format')) && !sub && req.method === 'GET')
            return html(res, code, renderHome(baseURL(req)).replace('<h1>talkbawt</h1>',
              `<h1>talkbawt</h1><div class="warn"><strong>${body.error.replace(/_/g, ' ')}</strong>${body.message}</div>`));
          return json(res, code, body);
        }
        if (isMeta && (req.method === 'GET' || req.method === 'HEAD')) {
          if (access.revoked) return json(res, 410, { error: 'revoked', message: 'This thread was revoked.' });
          return showMeta(req, res, access, req.method === 'HEAD');
        }
        if (!sub && req.method === 'GET') return await showThread(req, res, url, access, token);
        if (sub === '/messages' && req.method === 'POST') return await postMessage(req, res, access, token);
        if (sub === '/revoke' && req.method === 'POST') return revoke(req, res, access);
        return json(res, 405, { error: 'method_not_allowed' });
      }

      return json(res, 404, { error: 'not_found', message: `No route for ${req.method} ${path}. See ${baseURL(req)}/ for usage.` });
    } catch (err) {
      if (err?.code === 413 || err?.code === 400) return json(res, err.code, { error: 'bad_request', message: err.message });
      logger.error('[talkbawt]', err);
      if (!res.headersSent) return json(res, 500, { error: 'internal_error' });
    }
  }

  const server = createServer(handler);

  const sweeper = setInterval(() => {
    const n = store.sweepExpired(revokedRetentionMs);
    if (n) logger.log(`[talkbawt] swept ${n} expired or retired thread(s)`);
  }, 3600e3);
  sweeper.unref();

  return {
    server,
    handler,
    store,

    /** Resolves with { port, url }: the bound port and a local URL for it. Port 0 picks a free one. */
    listen(port = 0, host = '127.0.0.1') {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => {
          server.off('error', reject);
          const bound = server.address().port;
          const h = host.includes(':') ? `[${host}]` : host;
          // The local address to connect to; links handed out still use baseUrl when set.
          resolve({ port: bound, url: `http://${['0.0.0.0', '[::]'].includes(h) ? '127.0.0.1' : h}:${bound}` });
        });
      });
    },

    /** Stops listening, drops held long polls, and closes the database. */
    async close() {
      closing = true;
      clearInterval(sweeper);
      rateLimit.stop();
      await new Promise((resolve) => {
        if (!server.listening) return resolve();
        server.close(() => resolve());
        server.closeAllConnections?.();
      });
      for (let i = 0; waiters > 0 && i < 20; i++) await sleep(POLL_MS / 4);
      store.close();
    },
  };
}
