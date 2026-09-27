/* Library entry, for embedding talkbawt in another process:

     import { createTalkbawt } from 'talkbawt';
     const tb = createTalkbawt({ dbPath: '/home/me/.conductore/talkbawt/talkbawt.db' });
     const { url } = await tb.listen(0, '127.0.0.1');
     ...
     await tb.close();
*/
export { createTalkbawt } from './app.mjs';
export { signBody, SIGNATURE_WINDOW_S } from './guards.mjs';
