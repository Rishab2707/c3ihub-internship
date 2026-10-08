import http from 'node:http';
import https from 'node:https';
import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createHelperState } from './crypto/helper-state.js';

const tokens = [process.env.DUORAM_DEALER_TOKEN_A, process.env.DUORAM_DEALER_TOKEN_B];
if (tokens.some(token => !/^[0-9a-f]{64}$/i.test(token || '')) || tokens[0] === tokens[1]) {
  throw new Error('Configure distinct 256-bit dealer tokens for A and B');
}
const host = process.env.DUORAM_HOST || '127.0.0.1';
const port = Number(process.env.DUORAM_PORT_DEALER || 4103);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid dealer port');
const paths = [process.env.DUORAM_TLS_KEY_PATH, process.env.DUORAM_TLS_CERT_PATH, process.env.DUORAM_TLS_CA_PATH];
if (paths.some(Boolean) && !paths.every(Boolean)) throw new Error('Configure all TLS paths');
const tls = paths.every(Boolean) ? { key: readFileSync(paths[0]), cert: readFileSync(paths[1]), ca: readFileSync(paths[2]) } : null;
if (!['localhost', '127.0.0.1', '::1'].includes(host) && !tls) throw new Error('Remote dealer listeners require TLS');
const dealerInstance = randomUUID();
const clients = [null, null];
const size = Number(process.env.DB_SIZE || 2 ** 16);
if (!Number.isSafeInteger(size) || size < 1 || size > 1_000_000) throw new Error('Invalid helper database size');
const handleHelper = createHelperState(size);
const batches = new Map();
const seen = new Set();
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
function reply(res, status, data) { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(data)); }
function erase(shares) { if (shares) for (const vector of Object.values(shares)) vector.fill(0); }
function remove(id) {
  const batch = batches.get(id);
  if (!batch) return;
  clearTimeout(batch.timer); batch.shares.forEach(erase); batches.delete(id);
}
const server = (tls ? https : http).createServer(tls || {}, async (req, res) => {
  if (req.method !== 'POST' || !['/internal/triples', '/internal/preprocess', '/internal/discard', '/internal/read', '/internal/stage-update', '/internal/commit'].includes(req.url)) {
    return reply(res, 404, { error: 'Not found' });
  }
  const supplied = Buffer.from(req.headers['x-duoram-dealer-token'] || '');
  const party = tokens.findIndex(token => supplied.length === token.length && timingSafeEqual(supplied, Buffer.from(token)));
  if (party < 0) return reply(res, 404, { error: 'Not found' });
  try {
    const chunks = []; let length = 0;
    for await (const chunk of req) { length += chunk.length; if (length > 12_000) throw new Error('Request too large'); chunks.push(chunk); }
    const body = JSON.parse(Buffer.concat(chunks).toString());
    const { id, count, party: claimedParty, instanceId } = body;
    if (!uuid(id) || !uuid(instanceId) || claimedParty !== party ||
        (req.url === '/internal/triples' && (!Number.isInteger(count) || count < 1 || count > 2560))) {
      return reply(res, 400, { error: 'Invalid triple request' });
    }
    if (clients[party] !== null && clients[party] !== instanceId) return reply(res, 409, { error: 'Server lifetime changed; restart all three processes' });
    clients[party] = instanceId;
    if (req.url !== '/internal/triples') {
      const result = await handleHelper(req.url, body, party);
      return reply(res, 200, { ...result, id, party, dealerInstance });
    }
    let batch = batches.get(id);
    if (!batch) {
      if (seen.has(id)) return reply(res, 409, { error: 'Triple identifier already consumed or expired' });
      if (batches.size >= 32 || seen.size >= 100_000) return reply(res, 503, { error: 'Dealer capacity exhausted' });
      const bits = () => Array.from(randomBytes(count), byte => byte & 1);
      const x0 = bits(), x1 = bits(), y0 = bits(), y1 = bits(), t = bits();
      batch = { count, shares: [
        { x: x0, y: y0, z: x0.map((bit, i) => (bit & y1[i]) ^ t[i]) },
        { x: x1, y: y1, z: x1.map((bit, i) => (bit & y0[i]) ^ t[i]) },
      ], timer: null };
      t.fill(0); seen.add(id); batches.set(id, batch);
      batch.timer = setTimeout(() => remove(id), 120_000); batch.timer.unref();
    }
    if (batch.count !== count || !batch.shares[party]) return reply(res, 409, { error: 'Batch mismatch or duplicate retrieval' });
    const shares = batch.shares[party];
    reply(res, 200, { id, party, count, dealerInstance, shares });
    erase(shares); batch.shares[party] = null;
    if (batch.shares.every(value => value === null)) remove(id);
  } catch (error) { reply(res, 409, { error: error.message || 'Invalid helper request' }); }
});
server.listen(port, host, () => console.log(`DUORAM helper listening on ${tls ? 'https' : 'http'}://${host}:${port}`));
