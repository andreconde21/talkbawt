import { createServer } from 'node:http';
import * as store from './db.mjs';
import {
  newToken, hashPass, checkPass, parseTTL, scanForSecrets, rateLimit,
  isPreviewBot, clientHash, newCreatorKey, hashKey,
} from './guards.mjs';
import {
  renderThread, renderMarkdown, renderHome, SECURITY_NOTICE, REPLY_HELP,
} from './render.mjs';

const PORT = Number(process.env.PORT || 3000);
const MAX_BODY = 256 * 1024;          // per request
const MAX_TEXT = 200 * 1024;          // per message
const MAX_MESSAGES = 500;             // per thread
const DEFAULT_TTL = 1 * 86400e3;
const MAX_WAIT = 50;                  // seconds a long poll may be held open
const MAX_WAITERS = 100;              // concurrent held requests
const POLL_MS = 500;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let waiters = 0;

/* ---------- helpers ---------- */

const clientIP = (req) =>
  (req.headers['x-forwarded-for'] ?? '').toString().split(',')[0].trim() ||
  req.socket.remoteAddress || 'unknown';

const baseURL = (req) => {
  if (process.env.BASE_URL) return process.env.BASE_URL.replace(/\/$/, '');
  const proto = (req.headers['x-forwarded-proto'] ?? 'http').toString().split(',')[0];
  const host = (req.headers['x-forwarded-host'] ?? req.headers.host ?? `localhost:${PORT}`).toString();
  return `${proto}://${host}`;
};

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
      if (!raw.trim()) return resolve({});
      try { resolve(JSON.parse(raw)); }
      catch { reject(Object.assign(new Error('body must be valid JSON'), { code: 400 })); }
    });
    req.on('error', reject);
  });
}

const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const wantsHTML = (req, fmt) =>
  fmt === 'html' || (!fmt && (req.headers.accept ?? '').includes('text/html'));

/* ---------- access resolution ---------- */

function resolveAccess(req, token, url) {
  const row = store.findByToken(token);
  if (!row) return { error: [404, { error: 'not_found', message: 'No such thread. The link may have been revoked or it may have expired.' }] };

  const ip = clientIP(req);
  const ua = req.headers['user-agent'] ?? '';
  const ctx = { ip, ua, bot: isPreviewBot(ua), client: clientHash(ip, ua) };

  const deny = (code, body, note) => {
    store.log(row.id, 'denied', { role: row.tok_role, ok: false, ip, ua, note });
    return { error: [code, body] };
  };

  if (row.revoked || row.tok_revoked) return deny(410, { error: 'revoked', message: 'This link was revoked by its owner.' }, 'revoked');
  if (new Date(row.expires_at) < new Date()) return deny(410, { error: 'expired', message: `This thread expired on ${row.expires_at}.` }, 'expired');

  if (row.tok_role === 'guest') {
    if (row.pass_hash) {
      const pass = (req.headers['x-talkbawt-passphrase'] ?? url.searchParams.get('p') ?? '').toString();
      if (!checkPass(pass, row.pass_hash, row.pass_salt)) {
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
    if (row.max_reads != null && !ctx.bot
        && !store.isKnownReader(row.id, ctx.client)
        && store.countReaders(row.id) >= row.max_reads) {
      return deny(410, { error: 'read_limit_reached', message: 'This link has already been opened by the maximum number of readers.' }, 'read limit');
    }
  }

  return { thread: row, role: row.tok_role, ctx };
}

/* ---------- routes ---------- */

async function createThread(req, res, url) {
  const ip = clientIP(req);
  if (!rateLimit(`create:${ip}`, 120, 3600e3).ok)
    return json(res, 429, { error: 'rate_limited', message: 'Too many threads created from this address. Try again later.' });

  const b = await readBody(req);
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

  const id = store.createThread({
    title, mode, expiresAt: new Date(Date.now() + ttl).toISOString(),
    passHash: pass?.hash ?? null, passSalt: pass?.salt ?? null, maxReads,
    creatorHash: creatorKey ? hashKey(creatorKey) : null,
  });
  const guest = newToken('g');
  const owner = newToken('o');
  store.addToken(guest, id, 'guest', 'shared link');
  store.addToken(owner, id, 'owner', 'creator');
  store.addMessage(id, { author: from, role: 'owner', body: text });
  store.log(id, 'created', { role: 'owner', ip, ua: req.headers['user-agent'], note: findings.length ? 'secret scan overridden' : null });

  const base = baseURL(req);
  const shareURL = `${base}/t/${guest}`;
  const body = {
    ok: true,
    mode,
    title,
    expires_at: new Date(Date.now() + ttl).toISOString(),
    share_url: shareURL,
    owner_url: `${base}/t/${owner}`,
    passphrase_required: Boolean(pass),
    give_the_other_person: `Handoff for you: ${shareURL} — open it, or paste the URL to your ` +
      `coding agent and ask it to fetch it.${pass ? ' It is passphrase-protected; I will send the passphrase separately.' : ''}`,
    keep_private: 'owner_url is yours alone: it revokes the link and shows who has read it. Never share it.',
    next_steps: mode === 'thread'
      ? { watch_for_replies: `${shareURL}?since=1&wait=30&format=json`, revoke: `POST ${base}/t/${owner}/revoke` }
      : { revoke: `POST ${base}/t/${owner}/revoke` },
  };
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
  if (!rateLimit(`mine:${clientIP(req)}`, 60, 3600e3).ok)
    return json(res, 429, { error: 'rate_limited', message: 'Too many listings from this address. Try again later.' });

  const key = str(req.headers['x-talkbawt-key'], 200) || str(url.searchParams.get('key'), 200);
  if (!key) return json(res, 401, {
    error: 'key_required',
    message: 'Send your creator key as `X-Talkbawt-Key`. You get one by creating a thread with "remember": true.',
  });

  const base = baseURL(req);
  const rows = store.threadsByCreator(hashKey(key));
  return json(res, 200, {
    count: rows.length,
    note: 'Live threads you created with this key. Expired and revoked threads are not listed.',
    threads: rows.map((t) => {
      const toks = store.tokensFor(t.id);
      const guest = toks.find((k) => k.role === 'guest' && !k.revoked);
      const owner = toks.find((k) => k.role === 'owner');
      return {
        title: t.title,
        mode: t.mode,
        created_at: t.created_at,
        expires_at: t.expires_at,
        messages: store.maxSeq(t.id),
        distinct_readers: store.countReaders(t.id),
        max_reads: t.max_reads,
        passphrase_required: Boolean(t.pass_hash),
        share_url: guest ? `${base}/t/${guest.token}` : null,
        owner_url: owner ? `${base}/t/${owner.token}` : null,
      };
    }),
  });
}

async function showThread(req, res, url, access, token) {
  const { thread, role, ctx } = access;
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
      while (store.maxSeq(thread.id) <= since && Date.now() < deadline) {
        await sleep(POLL_MS);
        if (req.destroyed || res.writableEnded) return;   // caller gave up
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

  if (wantsHTML(req, fmt))
    return html(res, 200, renderThread({ thread, messages, base, token, role }), { etag });
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
      your_role: role,
    },
    messages: messages.map((m) => ({
      seq: m.seq, from: m.author, at: m.created_at, untrusted_content: m.body,
    })),
    how_to_reply: REPLY_HELP(base, token, thread.mode),
  };
  if (role === 'owner') {
    payload.owner = {
      share_url: `${base}/t/${store.tokensFor(thread.id).find((t) => t.role === 'guest' && !t.revoked)?.token ?? '(revoked)'}`,
      distinct_readers: store.countReaders(thread.id),
      max_reads: thread.max_reads,
      revoke: `POST ${base}/t/${token}/revoke`,
      access_log: store.accessLog(thread.id),
    };
  }
  return json(res, 200, payload, { etag });
}

async function postMessage(req, res, access, token) {
  const { thread, role, ctx } = access;
  if (thread.mode === 'handoff')
    return json(res, 409, { error: 'read_only', message: 'This is a one-shot handoff, not a thread. It cannot be replied to.' });
  if (!rateLimit(`post:${token}`, 60, 3600e3).ok)
    return json(res, 429, { error: 'rate_limited', message: 'Too many messages posted to this thread in the last hour.' });
  if (Number(store.messagesSince(thread.id, 0).length) >= MAX_MESSAGES)
    return json(res, 409, { error: 'thread_full', message: `A thread holds at most ${MAX_MESSAGES} messages.` });

  const b = await readBody(req);
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

  const seq = store.addMessage(thread.id, { author: from, role, body: text });
  store.log(thread.id, 'wrote', { role, note: `#${seq}`, ...ctx });
  return json(res, 201, { ok: true, seq, poll_for_replies: `${baseURL(req)}/t/${token}?since=${seq}&format=json` });
}

function revoke(req, res, access, token) {
  const { thread, role, ctx } = access;
  if (role !== 'owner')
    return json(res, 403, { error: 'owner_only', message: 'Only the owner_url can revoke this thread.' });
  store.revokeThread(thread.id);
  store.log(thread.id, 'revoked', { role, ...ctx });
  return json(res, 200, { ok: true, message: 'Revoked. The share link no longer resolves.' });
}

/* ---------- dispatch ---------- */

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const path = url.pathname.replace(/\/+$/, '') || '/';

  try {
    if (!rateLimit(`ip:${clientIP(req)}`, 240, 60e3).ok)
      return json(res, 429, { error: 'rate_limited', message: 'Slow down.' });

    if (path === '/healthz') return json(res, 200, { ok: true });
    if (path === '/robots.txt') return send(res, 200, 'text/plain', 'User-agent: *\nDisallow: /\n');
    if (path === '/' && req.method === 'GET') return html(res, 200, renderHome(baseURL(req)));
    if (path === '/api/threads' && req.method === 'POST') return await createThread(req, res, url);
    if (path === '/api/mine' && req.method === 'GET') return listMine(req, res, url);

    const m = path.match(/^\/t\/([A-Za-z0-9_]{10,80})(\/messages|\/revoke)?$/);
    if (m) {
      const [, token, sub] = m;
      const access = resolveAccess(req, token, url);
      if (access.error) {
        const [code, body] = access.error;
        if (wantsHTML(req, url.searchParams.get('format')) && !sub)
          return html(res, code, renderHome(baseURL(req)).replace('<h1>talkbawt</h1>',
            `<h1>talkbawt</h1><div class="warn"><strong>${body.error.replace(/_/g, ' ')}</strong>${body.message}</div>`));
        return json(res, code, body);
      }
      if (!sub && req.method === 'GET') return await showThread(req, res, url, access, token);
      if (sub === '/messages' && req.method === 'POST') return await postMessage(req, res, access, token);
      if (sub === '/revoke' && req.method === 'POST') return revoke(req, res, access, token);
      return json(res, 405, { error: 'method_not_allowed' });
    }

    return json(res, 404, { error: 'not_found', message: `No route for ${req.method} ${path}. See ${baseURL(req)}/ for usage.` });
  } catch (err) {
    if (err?.code === 413 || err?.code === 400) return json(res, err.code, { error: 'bad_request', message: err.message });
    console.error('[talkbawt]', err);
    return json(res, 500, { error: 'internal_error' });
  }
});

setInterval(() => {
  const n = store.sweepExpired();
  if (n) console.log(`[talkbawt] swept ${n} expired thread(s)`);
}, 3600e3).unref();

server.listen(PORT, () => console.log(`[talkbawt] listening on :${PORT}`));

for (const sig of ['SIGTERM', 'SIGINT'])
  process.on(sig, () => server.close(() => process.exit(0)));
