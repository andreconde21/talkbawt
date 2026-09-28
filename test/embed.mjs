/* Embedding test: starts talkbawt in-process the way the Conductore companion
   would, runs the smoke suite against it, then checks retention and shutdown.
   Usage: node test/embed.mjs */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { createTalkbawt } from '../src/index.mjs';

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}${extra ? ` — ${extra}` : ''}`); }
};
const post = (url, body) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
  .then(async (r) => ({ status: r.status, json: await r.json().catch(() => null) }));

const dir = mkdtempSync(join(tmpdir(), 'talkbawt-embed-'));
const quiet = { log() {}, error: console.error };
const tb = createTalkbawt({ dbPath: join(dir, 'nested', 'talkbawt.db'), logger: quiet });
const { port, url } = await tb.listen(0, '127.0.0.1');
console.log(`embedded talkbawt on ${url}\n`);
ok('listen(0) picks a free port', port > 0 && url === `http://127.0.0.1:${port}`);

console.log('smoke suite against the embedded server');
// Asynchronously: the server runs on this process's event loop.
const smoke = await new Promise((resolve) => execFile(process.execPath, ['test/smoke.mjs'],
  { env: { ...process.env, BASE: url }, timeout: 180e3 },
  (err, stdout) => resolve({ status: err ? (err.code ?? 1) : 0, stdout })));
const summary = smoke.stdout.trim().split('\n').pop();
ok(`smoke suite passes (${summary})`, smoke.status === 0, smoke.stdout.split('\n').filter((l) => l.includes('FAIL')).join('; '));

console.log('\nlinks and proxies');
const t = await post(`${url}/api/threads`, { from: 'companion', text: 'hello' });
ok('links use the bound address', t.json.share_url.startsWith(`${url}/t/g_`));
const spoof = await fetch(`${url}/api/threads`, { method: 'POST', body: JSON.stringify({ from: 'x', text: 'y' }),
  headers: { 'content-type': 'application/json', 'x-forwarded-host': 'evil.example', 'x-forwarded-for': '203.0.113.9' } }).then((r) => r.json());
ok('forwarded headers are ignored unless trustProxy is set', spoof.share_url.startsWith(url));

const fixed = createTalkbawt({ dbPath: join(dir, 'fixed.db'), baseUrl: 'https://talkbawt.example/', logger: quiet });
const f = await fixed.listen(0);
const fl = await post(`${f.url}/api/threads`, { from: 'x', text: 'y' });
ok('baseUrl overrides the links it hands out', fl.json.share_url.startsWith('https://talkbawt.example/t/g_'));
await fixed.close();

console.log('\ncreator key');
const ck = await post(`${url}/api/threads`, { from: 'companion', text: 'remember me', remember: true });
const mineHdr = await fetch(`${url}/api/mine`, { headers: { 'x-talkbawt-key': ck.json.creator_key } }).then((r) => r.json());
ok('an embedded server lists threads by the creator key header', mineHdr.count === 1 && mineHdr.threads[0].owner_url === ck.json.owner_url);
ok('and refuses the key in the URL', (await fetch(`${url}/api/mine?key=${ck.json.creator_key}`)).status === 400);

console.log('\nretention');
const r = await post(`${url}/api/threads`, { from: 'x', text: 'revoke then sweep' });
await post(`${r.json.owner_url}/revoke`, {});
tb.store.sweepExpired(7 * 86400e3);
ok('a revoked thread survives a sweep inside retention', (await fetch(`${r.json.owner_url}?format=json`)).status === 410
   && Boolean(tb.store.findByToken(r.json.owner_url.split('/t/')[1])));
tb.store.sweepExpired(0);
ok('and is deleted once retention has passed', (await fetch(`${r.json.owner_url}?format=json`)).status === 404);

console.log('\nshutdown');
const held = await post(`${url}/api/threads`, { from: 'x', text: 'wait on me' });
const pending = fetch(`${held.json.share_url}?since=1&wait=40&format=json`).then(() => 'answered', () => 'dropped');
await new Promise((res) => setTimeout(res, 300));
const t0 = Date.now();
await tb.close();
ok('close() returns promptly with a long poll held open', Date.now() - t0 < 5000, `${Date.now() - t0}ms`);
ok('and the held request ends', ['answered', 'dropped'].includes(await pending));
const refused = await fetch(`${url}/healthz`).then(() => false, () => true);
ok('the port is released', refused);

rmSync(dir, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
