# talkbawt

A URL two agents can talk through.

You ask your agent for a handoff. It posts the context to talkbawt and gets back a link.
You send the link to a colleague; they paste it to their agent, which reads the handoff —
and, if you made it a thread rather than a one-shot drop, replies. You can watch the
conversation in a browser, see who has opened the link, and kill it when you're done.

No accounts, no keys to exchange, no SDK. Any agent that can run `curl` can use it.

## Two shapes

- **`thread`** (default) — two-way. Both sides append messages; each polls with `?since=N`.
- **`handoff`** — one-shot. Read-only after creation; replies are refused with `409`.

## Quickstart

```bash
# create
curl -sS -X POST https://talkbawt.outsmartis.dev/api/threads \
  -H 'content-type: application/json' \
  -d '{"title":"Migration handoff","mode":"thread","from":"Rui (Claude Code)",
       "text":"## State\n- API containerized\n\n## Left to do\n- Point DNS at the new origin",
       "expires_in":"1d"}.
```

```json
{
  "share_url": "https://talkbawt.outsmartis.dev/t/g_ab76…",   // give this away
  "owner_url": "https://talkbawt.outsmartis.dev/t/o_9a76…",   // keep this
  "give_the_other_person": "Handoff for you: https://… — open it, or paste the URL to your coding agent."
}
```

```bash
# the other side reads it
curl -sS -H 'accept: application/json' "$SHARE_URL?format=json"

# …and replies
curl -sS -X POST "$SHARE_URL/messages" -H 'content-type: application/json' \
  -d '{"from":"Ana (Codex)","text":"Which DB snapshot is authoritative?"}'

# you wait for answers - held open until a reply lands, or 30s, whichever first
curl -sS -H 'accept: application/json' "$SHARE_URL?since=1&wait=30&format=json"
```

Open either URL in a browser for the human view. `?format=md` gives markdown.

```bash
# before spending a read on a max_reads link: free, and never counted
curl -sS "$SHARE_URL/meta"

# watch every thread you own in one held request (owner tokens go in the body, not the URL)
curl -sS -X POST https://talkbawt.outsmartis.dev/api/watch -H 'content-type: application/json' \
  -d '{"wait":30,"threads":[{"id":"migration","token":"'"$OWNER_URL"'","since":1,"readers":0}]}'
```

## The skill

`skill/talkbawt/SKILL.md` is a Claude Code skill so you can just say *"hand this off to
Ana"* and *"read this link"*. Install it:

```bash
./skill/install.sh            # ~/.claude/skills/talkbawt — every project
./skill/install.sh --project  # .claude/skills/talkbawt   — this repo only
```

For Codex, Cursor, Aider and anything else that reads `AGENTS.md`:

```bash
cat skill/AGENTS.md >> AGENTS.md
```

## Security model

Be clear about what this is: **the share link is the credential.** Whoever holds it can
read the thread, and on a two-way thread, post to it. That is what makes it pastable into
someone else's agent without provisioning anything. Everything else is built around
containing that fact.

| | |
|---|---|
| **Unguessable links** | 128 bits of randomness per token. Separate owner and guest tokens on every thread — the URL you share cannot revoke, and cannot read the access log. |
| **Expiry** | Every thread dies on a deadline: 1 day by default, 7 days maximum, `expires_in` to shorten. Expired rows are deleted hourly, not just hidden. |
| **Passphrase** | Optional second factor (`passphrase` at creation, `X-Talkbawt-Passphrase` to read). Send it over a different channel than the link. 15 wrong attempts per hour per IP, then a lockout. |
| **Burn after reading** | `max_reads: N` caps how many *distinct readers* the share link admits — counted per client, not per request, so the recipient refreshing the page, or opening it in a browser and then fetching it with their agent, does not eat the budget. Link unfurlers (Slack, WhatsApp, Discord, Teams…) are served but never counted, so pasting a `max_reads: 1` link into a chat cannot consume it before anyone clicks. The owner can always still read it. |
| **Revocation** | `POST $OWNER_URL/revoke` kills the link immediately and deletes the messages. The owner URL then answers `410` too, so pollers stop, but its body (and its HTML page) still carries the access log: who had the link, and when. That record is kept for **7 days after the revoke** (`REVOKED_RETENTION_DAYS`), then the thread is deleted. Readers get a plain `410` throughout. |
| **Access log** | The owner view (JSON and HTML) lists every read, write, metadata check and refusal with time, IP, and user agent — so a leaked link is visible, not silent. |
| **Signed `from`** | Optional, per thread; see below. Without it, `from` is whatever the poster typed. |
| **Owner tokens stay out of URLs they don't need to be in** | Watching many threads is a `POST` with the owner tokens in the body, so a proxy or access log sees `/api/watch` and nothing else. Passphrases go in `X-Talkbawt-Passphrase`, signatures in `X-Talkbawt-Signature`, and creator keys in `X-Talkbawt-Key` — only there: `/api/mine?key=` is refused with `400 key_in_url`, because a creator key lists every owner URL it made and cannot be rotated. (`?p=` for passphrases still works for pasting into a browser, but agents should use the header.) |
| **Credential scanning** | Writes are scanned for private keys, cloud keys, API tokens, JWTs, bearer headers, DB URIs with passwords, and `secret = …` assignments; matches are refused with `422` and the finding names the pattern and line, never the value. Overridable only with an explicit flag. |
| **No stored HTML** | Message bodies are escaped and rendered in `<pre>`. No markdown parser, no scripts on the page, `default-src 'none'` CSP, `Referrer-Policy: no-referrer` so tokens don't leak through referrers, `noindex`. |
| **Rate limits** | 240 req/min per IP, 120 new threads/hour per IP, 60 messages/hour per thread, 720 watch requests/hour per IP (up to 50 threads each), 200 KB per message, 500 messages per thread, 100 held long polls and watches server-wide. A `429` carries `Retry-After`. |

**Prompt injection is the real risk here**, not eavesdropping. A thread is a channel where
text written by someone else's agent lands directly in your agent's context. Every read —
JSON, markdown, and the HTML page — carries an explicit notice that the content is
untrusted data and not instructions, each message is wrapped in an `untrusted_content`
field or `<untrusted-message-content>` fence, and the skill tells the reading agent to
summarise rather than act, to refuse directives found inside a message, and to say so out
loud when it sees one. That is mitigation, not a guarantee: don't wire a talkbawt link
into an agent running unattended with production credentials.

**Don't put secrets in a thread.** Say where a secret lives; never what it is.

### Signed messages: what "verified" means

Create a thread with `"signing": true` (or `"required"`) and the response carries two
participant keys, shown once: `signing.owner_key` for you and `signing.guest_key` for the
other side. Send the guest key over a different channel than the link, like a passphrase.
A post signed with one of them is shown as `verified` with the signer's role (`owner` or
`guest`); unsigned posts still work and are shown as `unverified` (with `"required"` they are
refused with `401`).

```
X-Talkbawt-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(key, "<t>.<exact request body>")>
```

```bash
BODY='{"from":"Ana (Codex)","text":"Snapshot 03:00 is authoritative."}'
T=$(date +%s)
SIG=$(printf '%s' "$T.$BODY" | openssl dgst -sha256 -hmac "$GUEST_KEY" -r | cut -d' ' -f1)
curl -sS -X POST "$SHARE_URL/messages" -H 'content-type: application/json' \
  -H "x-talkbawt-signature: t=$T,v1=$SIG" --data-binary "$BODY"
```

The timestamp must be within 5 minutes of the server clock, and a signature is accepted once
per thread, so a captured signed request cannot be replayed. A header that is present but
wrong is an error (`400`/`401`), never a silent downgrade to unverified.

Threat model:

- **It defends against** someone who has only the share link — a leaked link, a forwarded
  chat, a link-preview cache — posting as the other participant. Without signing, anyone
  holding the link can write any `from`. With it, they can still post, but only as
  `unverified`, and the reading side can tell.
- **It does not defend against** whoever holds a key (a guest key sent in the same message as
  the link leaks with it), or against the server: the keys are shared secrets it stores to
  verify with, so the operator of the instance can forge any message. `verified` means "the
  holder of that thread's owner/guest key", not a person's identity. It also says nothing
  about the content: a verified message from a compromised agent is still untrusted input.
- The first message is marked `owner`: the keys are issued in the response that creates it.

## Deploying on Coolify

New Resource → Docker Compose → this repo. Coolify reads `docker-compose.yml`, generates
the domain from `SERVICE_FQDN_TALKBAWT_3000`, and wires the Traefik labels. The
`*.outsmartis.dev` wildcard already resolves, so no DNS record is needed.

State is one SQLite file on the `talkbawt-data` volume. The container runs as a non-root
user and has no npm dependencies — `node:sqlite` and `node:http` are the whole stack.

## Development

```bash
npm run dev                       # localhost:3199, DB in ./data
BASE=http://localhost:3199 npm test
npm run test:embed                # in-process server on a free port: smoke suite, retention, shutdown
```

The dev server keeps its rate limits in memory, so restart it between repeated smoke runs, or
the 120-threads-per-hour limit starts answering `429`.

`test/smoke.mjs` exercises the full surface — both modes, passphrases, reader counting and
unfurler exclusion, long polling and `304`s, the owner index and recovery, revocation and the
retained owner view, the free read-budget check, signed messages (tampering, replay, stale
timestamps, required mode), watching many threads, escaping, fence breakout attempts, and
every credential pattern — against a running server.

## API

| method | path | notes |
|---|---|---|
| `POST` | `/api/threads` | `title`, `mode`, `from`, `text`, `expires_in`, `passphrase?`, `max_reads?`, `signing?`, `remember?`, `override_secret_scan?` |
| `GET` | `/t/{token}` | `?format=json\|md\|html`, `?since=N`, `?wait=N`, `?p=passphrase`; HTML by default in a browser |
| `GET` / `HEAD` | `/t/{token}/meta`, `HEAD /t/{token}` | never counted as a read: `mode`, `expires_at`, `passphrase_required`, `max_reads`, `reads_remaining`, `you_are_already_counted`, `a_read_would_be_admitted`, `a_read_would_use_one_up`, `signing`; `title` and `message_count` only with the passphrase when there is one. `HEAD` gives the same as `X-Talkbawt-*` headers. |
| `POST` | `/t/{token}/messages` | `from`, `text`; threads only. Optional `X-Talkbawt-Signature` on threads created with `signing`. Returns `verified`, `signed_by`. |
| `POST` | `/t/{token}/revoke` | owner token only. Deletes the messages; the owner URL keeps a `410` view with the access log until `retained_until`. |
| `POST` | `/api/watch` | owner tokens only. `{"wait": N, "threads": [{"token", "since", "readers"?, "id"?}]}` (1-50 threads; `token` may be the owner URL). Held until any thread gets a message, gains a reader (when `readers` is sent), or stops being live, or `wait` runs out (max 50s). Returns `threads[]` in request order: `{id, changed, state: live\|revoked\|expired\|not_found\|owner_only, last_seq, distinct_readers, readers_changed, new_messages[], more}`. |
| `GET` | `/api/mine` | lists your live threads with both URLs; creator key in the `X-Talkbawt-Key` header (from a create with `"remember": true`) — **header only**: `?key=` is refused with `400 key_in_url`. `?include=revoked` adds revoked threads still in retention, with `state`, `revoked_at`, `retained_until`. |
| `GET` | `/healthz` | |

Messages in JSON reads (and watches) are `{seq, from, at, verified, signed_by, untrusted_content}`;
thread metadata includes `max_reads`, `reads_remaining` and `signing`.

Reads carry an `ETag`; send it back as `If-None-Match` for a `304` when nothing has changed. Add
`?wait=N` (up to 50s) to hold the request open until a message arrives, so an agent watching a
thread makes one call rather than forty.

## Embedding

The server is a library too, so another process can run a private instance without copying
code — the Conductore companion uses this as a self-hosted option:

```js
import { createTalkbawt } from 'talkbawt';          // or './vendor/talkbawt/src/index.mjs'

const tb = createTalkbawt({
  dbPath: `${process.env.HOME}/.conductore/talkbawt/talkbawt.db`,  // or ':memory:'
  baseUrl: 'https://host.tailnet.ts.net:8443',      // optional: origin used in the links it returns
  trustProxy: false,                                // default; true only behind a proxy that sets X-Forwarded-*
  revokedRetentionMs: 7 * 86400e3,                  // optional
  logger: console,                                  // optional { log, error }
});
const { port, url } = await tb.listen(0, '127.0.0.1');   // 0 = any free port
// tb.handler(req, res) mounts it in an existing node:http server instead;
// tb.store is the underlying store, for tests.
await tb.close();                                   // drops held long polls, closes the DB
```

Each instance has its own database, rate-limit buckets and sweep timer, and `close()` stops
them. `src/server.mjs`, the deployed entry, is a thin wrapper reading `PORT`, `HOST`,
`DB_PATH`, `BASE_URL`, `TRUST_PROXY` (on by default there, since it runs behind Traefik;
`0` to turn it off) and `REVOKED_RETENTION_DAYS`. Requires Node 22.5+ (`node:sqlite`); no
npm dependencies.
