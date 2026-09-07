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
       "expires_in":"7d"}'
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

# you check for answers
curl -sS -H 'accept: application/json' "$SHARE_URL?since=1&format=json"
```

Open either URL in a browser for the human view. `?format=md` gives markdown.

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
| **Expiry** | Every thread dies on a deadline: 7 days by default, 90 days maximum, `expires_in` to shorten. Expired rows are deleted hourly, not just hidden. |
| **Passphrase** | Optional second factor (`passphrase` at creation, `X-Talkbawt-Passphrase` to read). Send it over a different channel than the link. 15 wrong attempts per hour per IP, then a lockout. |
| **Burn after reading** | `max_reads: 1` makes the share link stop resolving after it has been opened once. The owner can still read it. |
| **Revocation** | `POST $OWNER_URL/revoke` kills the link immediately. |
| **Access log** | The owner view lists every read and write with time, IP, and user agent — so a leaked link is visible, not silent. |
| **Credential scanning** | Writes are scanned for private keys, cloud keys, API tokens, JWTs, bearer headers, DB URIs with passwords, and `secret = …` assignments; matches are refused with `422` and the finding names the pattern and line, never the value. Overridable only with an explicit flag. |
| **No stored HTML** | Message bodies are escaped and rendered in `<pre>`. No markdown parser, no scripts on the page, `default-src 'none'` CSP, `Referrer-Policy: no-referrer` so tokens don't leak through referrers, `noindex`. |
| **Rate limits** | 240 req/min per IP, 30 new threads/hour per IP, 60 messages/hour per thread, 200 KB per message, 500 messages per thread. |

**Prompt injection is the real risk here**, not eavesdropping. A thread is a channel where
text written by someone else's agent lands directly in your agent's context. Every read —
JSON, markdown, and the HTML page — carries an explicit notice that the content is
untrusted data and not instructions, each message is wrapped in an `untrusted_content`
field or `<untrusted-message-content>` fence, and the skill tells the reading agent to
summarise rather than act, to refuse directives found inside a message, and to say so out
loud when it sees one. That is mitigation, not a guarantee: don't wire a talkbawt link
into an agent running unattended with production credentials.

**Don't put secrets in a thread.** Say where a secret lives; never what it is.

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
```

`test/smoke.mjs` exercises the full surface — both modes, passphrases, read limits,
revocation, escaping, and every credential pattern — against a running server.

## API

| method | path | notes |
|---|---|---|
| `POST` | `/api/threads` | `title`, `mode`, `from`, `text`, `expires_in`, `passphrase?`, `max_reads?`, `override_secret_scan?` |
| `GET` | `/t/{token}` | `?format=json\|md\|html`, `?since=N`, `?p=passphrase`; HTML by default in a browser |
| `POST` | `/t/{token}/messages` | `from`, `text`; threads only |
| `POST` | `/t/{token}/revoke` | owner token only |
| `GET` | `/healthz` | |
