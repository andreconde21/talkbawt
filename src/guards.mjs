import { randomBytes, createHash, scryptSync, timingSafeEqual } from 'node:crypto';

/* ---------- tokens ---------- */

export const newToken = (prefix) => `${prefix}_${randomBytes(16).toString('hex')}`;

/* A per-response marker, so a message body cannot forge the fence that
   separates untrusted content from our own text. See render.mjs. */
export const newMarker = () => randomBytes(6).toString('hex');

/* Creator keys group the threads one person made, for GET /api/mine.
   Generated server-side so they are never weak, stored only as a hash. */
export const newCreatorKey = () => `k_${randomBytes(24).toString('hex')}`;
export const hashKey = (key) => createHash('sha256').update(String(key)).digest('hex');

/* ---------- client identity ---------- */

/* Distinct readers are counted per client, not per request, so refreshing a
   page - or a browser and an agent on the same machine - does not burn a
   max_reads budget. Salted per process start: these never need to outlive it,
   and it keeps raw addresses out of the table. */
const CLIENT_SALT = randomBytes(16).toString('hex');
export const clientHash = (ip, ua) =>
  createHash('sha256').update(`${CLIENT_SALT}|${ip}|${ua ?? ''}`).digest('hex').slice(0, 32);

/* Link unfurlers fetch a URL the moment it is pasted into a chat. Counting
   that as a read burns burn-after-reading links before the recipient ever
   clicks, and fills the access log with arrivals nobody made. Serve them,
   but do not count them. */
const PREVIEW_BOTS = /slackbot|slack-imgproxy|discordbot|whatsapp|telegrambot|twitterbot|facebookexternalhit|facebot|linkedinbot|skypeuripreview|redditbot|embedly|quora link preview|outlook|teams|googlebot|bingbot|applebot|duckduckbot|yandexbot|baiduspider|semrushbot|ahrefsbot|preview|unfurl|link-?check|monitoring|uptime|pingdom|curl-preview/i;
export const isPreviewBot = (ua) => PREVIEW_BOTS.test(String(ua ?? ''));

/* ---------- passphrase ---------- */

export function hashPass(pass) {
  const salt = randomBytes(16).toString('hex');
  return { hash: scryptSync(pass, salt, 32).toString('hex'), salt };
}

export function checkPass(pass, hash, salt) {
  if (!hash) return true;
  if (typeof pass !== 'string' || pass.length === 0) return false;
  const a = Buffer.from(hash, 'hex');
  const b = scryptSync(pass, salt, 32);
  return a.length === b.length && timingSafeEqual(a, b);
}

/* ---------- durations ---------- */

const MAX_TTL_MS = 7 * 24 * 3600 * 1000;

export function parseTTL(spec, fallbackMs) {
  if (spec == null) return fallbackMs;
  const m = String(spec).trim().match(/^(\d+)\s*([mhdw])$/i);
  if (!m) return null;
  const n = Number(m[1]);
  const unit = { m: 60e3, h: 3600e3, d: 86400e3, w: 604800e3 }[m[2].toLowerCase()];
  const ms = n * unit;
  if (ms <= 0 || ms > MAX_TTL_MS) return null;
  return ms;
}

/* ---------- credential scanning ----------
   Refuses to store content that looks like it contains live credentials.
   A shared link is a shared secret; secrets should never ride inside one.
   Reports only the pattern name and line number - never the matched value. */

const SECRET_PATTERNS = [
  ['private-key-block',   /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/],
  ['aws-access-key',      /\bAKIA[0-9A-Z]{16}\b/],
  ['anthropic-api-key',   /\bsk-ant-[A-Za-z0-9_-]{20,}/],
  ['openai-api-key',      /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/],
  ['github-token',        /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b/],
  ['slack-token',         /\bxox[abprs]-[A-Za-z0-9-]{10,}/],
  ['google-api-key',      /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['laravel-sanctum-token', /\b\d+\|[A-Za-z0-9]{38,}\b/],
  ['jwt',                 /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/],
  ['discord-webhook',     /https:\/\/(?:\w+\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]{20,}/],
  ['bearer-header',       /\bAuthorization\s*:\s*Bearer\s+\S{16,}/i],
  ['db-uri-password',     /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:/@]+:[^\s@/]{6,}@/i],
  ['assigned-credential', /\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|pwd)\b\s*[:=]\s*["']?[^\s"'`,;]{12,}/i],
];

export function scanForSecrets(text) {
  const findings = [];
  const lines = String(text).split('\n');
  for (let i = 0; i < lines.length; i++) {
    for (const [name, re] of SECRET_PATTERNS) {
      if (re.test(lines[i])) findings.push({ pattern: name, line: i + 1 });
    }
  }
  return findings;
}

/* ---------- rate limiting (in-memory sliding window) ---------- */

const buckets = new Map();

export function rateLimit(key, limit, windowMs) {
  const now = Date.now();
  const hits = (buckets.get(key) ?? []).filter((t) => now - t < windowMs);
  if (hits.length >= limit) {
    buckets.set(key, hits);
    return { ok: false, retryAfter: Math.ceil((windowMs - (now - hits[0])) / 1000) };
  }
  hits.push(now);
  buckets.set(key, hits);
  return { ok: true };
}

setInterval(() => {
  const cutoff = Date.now() - 3600e3;
  for (const [k, v] of buckets) {
    const kept = v.filter((t) => t > cutoff);
    if (kept.length) buckets.set(k, kept);
    else buckets.delete(k);
  }
}, 600e3).unref();
