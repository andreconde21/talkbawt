/* End-to-end smoke test. Usage: BASE=http://localhost:3199 node test/smoke.mjs */
const BASE = process.env.BASE || 'http://localhost:3199';

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}${extra ? ` — ${extra}` : ''}`); }
};

const call = async (method, url, body, headers = {}) => {
  const res = await fetch(url, {
    method,
    headers: { 'content-type': 'application/json', accept: 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* html/markdown */ }
  return { status: res.status, json, text, type: res.headers.get('content-type') };
};

const create = (body) => call('POST', `${BASE}/api/threads`, body);

console.log(`talkbawt smoke test against ${BASE}\n`);

/* --- two-way thread --- */
console.log('two-way thread');
const t = await create({ title: 'Migration handoff', mode: 'thread', from: 'Rui (Claude Code)', text: 'Context: the API is containerized.' });
ok('create returns 201', t.status === 201, `got ${t.status}`);
ok('share_url and owner_url differ', t.json.share_url !== t.json.owner_url);
const share = t.json.share_url, owner = t.json.owner_url;

const read = await call('GET', `${share}?format=json`);
ok('guest reads the thread', read.status === 200 && read.json.messages.length === 1);
ok('first message body is intact', read.json.messages[0].untrusted_content.includes('containerized'));
ok('response carries the security notice', /UNTRUSTED CONTENT/.test(read.json.security_notice ?? ''));
ok('content is labelled untrusted', 'untrusted_content' in read.json.messages[0]);
ok('guest is told how to reply', typeof read.json.how_to_reply.append_a_message === 'string');
ok('guest cannot see the access log', read.json.owner === undefined);

const reply = await call('POST', `${share}/messages`, { from: 'Ana (Codex)', text: 'Which DB snapshot is authoritative?' });
ok('guest can reply', reply.status === 201 && reply.json.seq === 2, `got ${reply.status}`);

const poll = await call('GET', `${share}?since=1&format=json`);
ok('since= returns only new messages', poll.json.messages.length === 1 && poll.json.messages[0].seq === 2);

const ownerView = await call('GET', `${owner}?format=json`);
ok('owner sees the access log', Array.isArray(ownerView.json.owner?.access_log) && ownerView.json.owner.access_log.length > 0);
ok('owner sees the read count', typeof ownerView.json.owner.guest_reads === 'number');

const htmlView = await fetch(share, { headers: { accept: 'text/html' } });
const htmlBody = await htmlView.text();
ok('browsers get HTML', htmlView.headers.get('content-type').startsWith('text/html'));
ok('HTML page warns agents', htmlBody.includes('Notice for AI agents'));
ok('HTML sets a strict CSP', (htmlView.headers.get('content-security-policy') ?? '').includes("default-src 'none'"));
ok('HTML sends no referrer', htmlView.headers.get('referrer-policy') === 'no-referrer');

const md = await call('GET', `${share}?format=md`);
ok('markdown view fences untrusted content', md.text.includes('<untrusted-message-content>'));

/* --- XSS is escaped, never rendered --- */
console.log('\nhostile content');
const x = await create({ title: '<img src=x onerror=alert(1)>', from: 'attacker', text: '<script>alert(1)</script>' });
const xHtml = await (await fetch(x.json.share_url, { headers: { accept: 'text/html' } })).text();
ok('script tags are escaped in the body', !xHtml.includes('<script>alert(1)</script>') && xHtml.includes('&lt;script&gt;'));
ok('titles are escaped too', !xHtml.includes('<img src=x onerror'));

/* --- one-shot handoff --- */
console.log('\none-shot handoff');
const h = await create({ title: 'Read-only handoff', mode: 'handoff', from: 'Rui', text: 'Everything you need is here.' });
ok('handoff is created', h.status === 201 && h.json.mode === 'handoff');
const hReply = await call('POST', `${h.json.share_url}/messages`, { from: 'Ana', text: 'hi' });
ok('handoff rejects replies with 409', hReply.status === 409, `got ${hReply.status}`);
const hRead = await call('GET', `${h.json.share_url}?format=json`);
ok('handoff is still readable', hRead.status === 200);

/* --- passphrase --- */
console.log('\npassphrase');
const p = await create({ title: 'Protected', from: 'Rui', text: 'sensitive-ish context', passphrase: 'correct horse battery' });
ok('passphrase thread is created', p.status === 201 && p.json.passphrase_required === true);
ok('no passphrase is rejected', (await call('GET', `${p.json.share_url}?format=json`)).status === 401);
ok('wrong passphrase is rejected', (await call('GET', `${p.json.share_url}?format=json`, undefined, { 'x-talkbawt-passphrase': 'nope' })).status === 401);
ok('right passphrase is accepted', (await call('GET', `${p.json.share_url}?format=json`, undefined, { 'x-talkbawt-passphrase': 'correct horse battery' })).status === 200);
ok('owner_url bypasses the passphrase', (await call('GET', `${p.json.owner_url}?format=json`)).status === 200);
ok('short passphrase is refused at creation', (await create({ title: 'x', from: 'x', text: 'x', passphrase: 'abc' })).status === 400);

/* --- burn after reading --- */
console.log('\nread limit');
const b = await create({ title: 'Burn', from: 'Rui', text: 'read me once', max_reads: 1 });
ok('first read succeeds', (await call('GET', `${b.json.share_url}?format=json`)).status === 200);
ok('second read is gone', (await call('GET', `${b.json.share_url}?format=json`)).status === 410);
ok('owner can still read it', (await call('GET', `${b.json.owner_url}?format=json`)).status === 200);

/* --- credential scanning --- */
console.log('\ncredential scanning');
const creds = [
  ['bearer header', 'Authorization: Bearer 25|abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH'],
  ['anthropic key', 'use sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAA to auth'],
  ['aws key', 'AKIAIOSFODNN7EXAMPLE'],
  ['private key', '-----BEGIN OPENSSH PRIVATE KEY-----'],
  ['db uri', 'postgres://app:hunter2hunter2@db.internal:5432/prod'],
  ['assigned secret', 'client_secret = 8f2b91ac44de77c1'],
  ['github token', 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'],
];
for (const [name, text] of creds)
  ok(`blocks ${name}`, (await create({ title: 'x', from: 'x', text })).status === 422);
ok('override flag lets it through', (await create({ title: 'x', from: 'x', text: 'AKIAIOSFODNN7EXAMPLE', override_secret_scan: true })).status === 201);
ok('ordinary prose is not blocked', (await create({ title: 'x', from: 'x', text: 'The password reset flow is broken; the token expires too fast.' })).status === 201);
ok('replies are scanned too', (await call('POST', `${share}/messages`, { from: 'Ana', text: 'AKIAIOSFODNN7EXAMPLE' })).status === 422);

/* --- revocation and expiry --- */
console.log('\nrevocation and expiry');
ok('guest cannot revoke', (await call('POST', `${share}/revoke`)).status === 403);
ok('owner can revoke', (await call('POST', `${owner}/revoke`)).status === 200);
ok('revoked share link is gone', (await call('GET', `${share}?format=json`)).status === 410);
ok('bad token is 404', (await call('GET', `${BASE}/t/g_00000000000000000000000000000000?format=json`)).status === 404);
ok('bad expires_in is refused', (await create({ title: 'x', from: 'x', text: 'x', expires_in: 'banana' })).status === 400);
ok('over-long ttl is refused', (await create({ title: 'x', from: 'x', text: 'x', expires_in: '52w' })).status === 400);
ok('missing text is refused', (await create({ title: 'x', from: 'x' })).status === 400);

/* --- misc --- */
console.log('\nmisc');
ok('home page renders', (await fetch(`${BASE}/`, { headers: { accept: 'text/html' } })).status === 200);
ok('robots.txt disallows crawling', (await (await fetch(`${BASE}/robots.txt`)).text()).includes('Disallow: /'));
ok('unknown route is 404', (await call('GET', `${BASE}/nope`)).status === 404);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
