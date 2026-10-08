import http from 'node:http';
import https from 'node:https';
import { readFileSync } from 'node:fs';

export async function requestHelper(path, payload, party, instanceId) {
  if (!path.startsWith('/internal/')) throw new Error('Invalid helper route');
  const target = new URL(path, process.env.DUORAM_DEALER_URL || 'http://127.0.0.1:4103');
  if (!['http:', 'https:'].includes(target.protocol) ||
      (target.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(target.hostname))) {
    throw new Error('Remote dealer connections require HTTPS');
  }
  const token = process.env[party === 0 ? 'DUORAM_DEALER_TOKEN_A' : 'DUORAM_DEALER_TOKEN_B'];
  if (!/^[0-9a-f]{64}$/i.test(token || '')) throw new Error('Configure this server\'s private dealer token');
  const body = Buffer.from(JSON.stringify({ ...payload, party, instanceId }));
  return new Promise((resolve, reject) => {
    const req = (target.protocol === 'https:' ? https : http).request(target, {
      method: 'POST', agent: false,
      ca: process.env.DUORAM_TLS_CA_PATH ? readFileSync(process.env.DUORAM_TLS_CA_PATH) : undefined,
      headers: { 'content-type': 'application/json', 'content-length': body.length, 'x-duoram-dealer-token': token },
    }, res => {
      const chunks = []; let length = 0;
      res.on('data', chunk => { length += chunk.length; if (length > 100_000) req.destroy(new Error('Dealer response too large')); else chunks.push(chunk); });
      res.on('error', reject);
      res.on('end', () => {
        try {
          const result = JSON.parse(Buffer.concat(chunks).toString());
          if (res.statusCode !== 200) throw new Error(result.error || 'Dealer request failed');
          if (result.id !== payload.id || result.party !== party ||
              !/^[0-9a-f-]{36}$/i.test(result.dealerInstance || '')) throw new Error('Mismatched helper response');
          if (path === '/internal/triples' && result.count !== payload.count) throw new Error('Mismatched triple count');
          resolve(result);
        } catch (error) { reject(error); }
      });
    });
    req.setTimeout(120_000, () => req.destroy(new Error('Helper request timed out')));
    req.on('error', reject); req.end(body);
  });
}
