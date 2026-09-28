/* CLI entry: the deployed service. Everything else lives in app.mjs, which an
   embedding process can import instead (see src/index.mjs). */
import { createTalkbawt } from './app.mjs';

const PORT = Number(process.env.PORT || 3000);

const app = createTalkbawt({
  dbPath: process.env.DB_PATH || '/data/talkbawt.db',
  baseUrl: process.env.BASE_URL || null,
  // The deployment sits behind Traefik, which sets the forwarded headers.
  // Set TRUST_PROXY=0 when running it exposed without a proxy.
  trustProxy: process.env.TRUST_PROXY !== '0',
  revokedRetentionMs: process.env.REVOKED_RETENTION_DAYS
    ? Number(process.env.REVOKED_RETENTION_DAYS) * 86400e3 : undefined,
});

const { port } = await app.listen(PORT, process.env.HOST || '0.0.0.0');
console.log(`[talkbawt] listening on :${port}`);

for (const sig of ['SIGTERM', 'SIGINT'])
  process.on(sig, () => app.close().then(() => process.exit(0)));
