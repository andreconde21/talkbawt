import { createServer } from 'node:http';
import * as store from './db.mjs';
import {
  newToken, hashPass, checkPass, parseTTL, scanForSecrets, rateLimit,
} from './guards.mjs';
import {
  renderThread, renderMarkdown, renderHome, SECURITY_NOTICE, REPLY_HELP,
} from './render.mjs';

const PORT = Number(process.env.PORT || 3000);
const MAX_BODY = 256 * 1024;          // per request
const MAX_TEXT = 200 * 1024;          // per message
const MAX_MESSAGES = 500;             // per thread
const DEFAULT_TTL = 1 * 86400e3;

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
const html = (res, code, body) =>
  send(res, code, 'text/html; charset=utf-8', body, {
    'content-security-policy':
      "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
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

  const ctx = { ip: clientIP(req), ua: req.headers['user-agent'] };
  const deny = (code, body, note) => {
    store.log(row.id, 'denied', { role: row.tok_role, ok: false, note, ...ctx });
    return { error: [code, body] };
  };

  if (row.revoked || row.tok_revoked) return deny(410, { error: 'revoked', message: 'This link was revoked by its owner.' }, 'revoked');
  if (new Date(row.expires_at) < new Date()) return deny(410, { error: 'expired', message: `This thread expired on ${row.expires_at}.` }, 'expired');

  if (row.tok_role === 'guest') {
    if (row.pass_hash) {
      const pass = (req.headers['x-talkbawt-passphrase'] ?? url.searchParams.get('p') ?? '').toString();
      if (!checkPass(pass, row.pass_hash, row.pass_salt)) {
        const rl = rateLimit(`badpass:${ctx.ip}`, 15, 3600e3);
        if (!rl.ok) return deny(429, { error: 'too_many_attempts', message: 'Too many failed passphrase attempts.' }, 'passphrase lockout');
        return deny(401, {
          error: 'passphrase_required',
          message: 'This thread is passphrase-protected. Ask the person who sent you the link for the passphrase, then retry with header `X-Talkbawt-Passphrase: <passphrase>`.',
        }, 'bad passphrase');
      }
    }
    if (row.max_reads != null && row.guest_reads >= row.max_reads) {
      return deny(410, { error: 'read_limit_reached', message: 'This link has already been opened the maximum number of times.' }, 'read limit');
    }
  }

  return { thread: row, role: row.tok_role, ctx };
}

/* ---------- routes ---------- */

async function createThread(req, res, url) {
  const ip = clientIP(req);
  if (!rateLimit(`create:${ip}`, 30, 3600e3).ok)
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

  const id = store.createThread({
    title, mode, expiresAt: new Date(Date.now() + ttl).toISOString(),
    passHash: pass?.hash ?? null, passSalt: pass?.salt ?? null, maxReads,
  });
  const guest = newToken('g');
  const owner = newToken('o');
  store.addToken(guest, id, 'guest', 'shared link');
  store.addToken(owner, id, 'owner', 'creator');
  store.addMessage(id, { author: from, role: 'owner', body: text });
  store.log(id, 'created', { role: 'owner', ip, ua: req.headers['user-agent'], note: findings.length ? 'secret scan overridden' : null });

  const base = baseURL(req);
  const shareURL = `${base}/t/${guest}`;
  return json(res, 201, {
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
      ? { watch_for_replies: `${shareURL}?since=1&format=json`, revoke: `POST ${base}/t/${owner}/revoke` }
      : { revoke: `POST ${base}/t/${owner}/revoke` },
  });
}

function showThread(req, res, url, access, token) {
  const { thread, role, ctx } = access;
  const since = Number(url.searchParams.get('since') ?? 0) || 0;
  const messages = store.messagesSince(thread.id, since);
  const fmt = url.searchParams.get('format');
  const base = baseURL(req);

  if (role === 'guest') store.bumpReads(thread.id);
  store.log(thread.id, 'read', { role, ...ctx });

  if (wantsHTML(req, fmt)) return html(res, 200, renderThread({ thread, messages, base, token, role }));
  if (fmt === 'md' || fmt === 'markdown')
    return send(res, 200, 'text/markdown; charset=utf-8', renderMarkdown({ thread, messages, base, token }));

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
      guest_reads: thread.guest_reads,
      max_reads: thread.max_reads,
      revoke: `POST ${base}/t/${token}/revoke`,
      access_log: store.accessLog(thread.id),
    };
  }
  return json(res, 200, payload);
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
      if (!sub && req.method === 'GET') return showThread(req, res, url, access, token);
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
