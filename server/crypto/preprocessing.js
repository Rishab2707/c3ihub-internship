import { createHash, randomBytes } from 'node:crypto';
import { generateDuoramDpfShare } from './duoram-dpf.js';
import { createOnlineAndCallback } from './online-and.js';
import { waitForDpfControl } from './dpf-control-store.js';
import { waitForReadExchange } from './read-round-store.js';
import { dealerTriplePool, createDuAtallahAndCallback, generateOtDuAtallahTriplePool } from './du-atallah.js';

export function componentId(id, component) {
  const bytes = createHash('sha256').update(`DUORAM-COMPONENT-v13:${id}:${component}`).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
  const hex = bytes.toString('hex');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

export function beginPreprocessing(id, party, domainBits, contexts, mode = 'dealer') {
  if (!['dealer', 'ot'].includes(mode)) throw new TypeError('Invalid preprocessing mode');
  const randomIndexBits = Array.from(randomBytes(domainBits), byte => byte & 1);
  return { id, party, domainBits, mode, randomIndexBits, components: [], consumed: false };
}

export async function generatePreprocessedDpf(item, contexts, peerRequest, helperRequest, databaseSize) {
  // Three independently seeded DPFs at the same hidden random address.
  for (let component = 0; component < 3; component++) {
    const id = componentId(item.id, component);
    let pool;
    if (item.mode === 'dealer') {
      const batch = await helperRequest('/internal/triples', { id, count: item.domainBits * 128 });
      pool = dealerTriplePool(batch.shares, item.domainBits * 128);
    } else {
      const otMultiply = createOnlineAndCallback({ party: item.party, sessionId: id,
        senderContext: contexts.senderContext, receiverSeedPairs: contexts.receiverSeedPairs, peerRequest });
      pool = await generateOtDuAtallahTriplePool(item.domainBits * 128, otMultiply);
    }
    const exchangeOpenings = item.party === 0
      ? (roundId, shares) => peerRequest('/internal/mpc/triples/open', { sessionId: id, roundId, ...shares })
      : (roundId, shares) => waitForReadExchange(id, `triple:${roundId}`, shares);
    const andShares = createDuAtallahAndCallback({ pool, exchangeOpenings });
    const exchangeControlShares = item.party === 0
      ? (level, left, right, wordShare) => peerRequest('/internal/mpc/dpf/control', { sessionId: id, level, left, right, wordShare })
      : (level, left, right, wordShare) => waitForDpfControl(id, level, left, right, wordShare);
    try {
      const key = await generateDuoramDpfShare({ party: item.party, domainBits: item.domainBits,
        indexShareBits: item.randomIndexBits, andShares, exchangeControlShares,
        onEvaluation: evaluation => { item.components[component] = evaluation; } });
      // Helper gets only A's Blind0 key and B's Blind1 key. Never both
      // shares of any component, random index shares, or the Read keys.
      if (component === item.party + 1) item.helperKey = key;
      if (pool.remaining !== 0) throw new Error('Incomplete triple consumption');
    } finally { pool.discard(); }
  }
  const registered = await helperRequest('/internal/preprocess', {
    id: item.id, key: item.helperKey, databaseSize, domainBits: item.domainBits,
  });
  item.helperInstance = registered.dealerInstance;
  delete item.helperKey;
}

export function consumePreprocessing(item) {
  if (!item || item.consumed || item.components.length !== 3 || !item.helperInstance) {
    throw new Error('Fresh completed preprocessing is required');
  }
  item.consumed = true;
  return item;
}
