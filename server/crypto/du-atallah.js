import { createTriplePool } from './multiplication-triples.js';
import { randomBytes } from 'node:crypto';

export async function generateOtDuAtallahTriplePool(count, otMultiply) {
  if (!Number.isInteger(count) || count < 1 || count > 2560) throw new TypeError('Invalid triple count');
  const x = Array.from(randomBytes(count), byte => byte & 1);
  const y = Array.from(randomBytes(count), byte => byte & 1);
  try {
    // Swapped operands give c_p = (Y_p AND X_p) XOR
    // (Y_peer AND X_p) XOR T. Removing the local product leaves
    // Z_p = (X_p AND Y_peer) XOR T, the helper's same correlation.
    const products = await otMultiply(y, x);
    if (!Array.isArray(products) || products.length !== count || products.some(bit => bit !== 0 && bit !== 1)) {
      throw new Error('Invalid OT triple result');
    }
    const z = products.map((bit, i) => bit ^ (x[i] & y[i]));
    products.fill(0);
    return createTriplePool(x, y, z);
  } catch (error) { x.fill(0); y.fill(0); throw error; }
}

export function dealerTriplePool(shares, count) {
  for (const name of ['x', 'y', 'z']) {
    if (!Array.isArray(shares?.[name]) || shares[name].length !== count ||
        shares[name].some(bit => bit !== 0 && bit !== 1)) throw new TypeError('Invalid dealer triple shares');
  }
  return createTriplePool(shares.x, shares.y, shares.z);
}

// DUORAM Appendix A: Z0=(X0 AND Y1) XOR T, Z1=(X1 AND Y0) XOR T.
// Exchange masked local operands, not Beaver's reconstructed d/e openings.
export function createDuAtallahAndCallback({ pool, exchangeOpenings }) {
  let roundId = 0;
  return async (x, y) => {
    if (!Array.isArray(x) || !Array.isArray(y) || x.length !== y.length ||
        [...x, ...y].some(bit => bit !== 0 && bit !== 1)) throw new TypeError('Invalid AND operands');
    const triple = pool.take(x.length);
    try {
      const peer = await exchangeOpenings(roundId++, {
        dShare: x.map((bit, i) => bit ^ triple.a[i]),
        eShare: y.map((bit, i) => bit ^ triple.b[i]),
      });
      for (const name of ['dShare', 'eShare']) {
        if (!Array.isArray(peer?.[name]) || peer[name].length !== x.length ||
            peer[name].some(bit => bit !== 0 && bit !== 1)) throw new TypeError('Invalid masked Du-Atallah operands');
      }
      return x.map((bit, i) => (bit & (y[i] ^ peer.eShare[i])) ^
        (triple.b[i] & peer.dShare[i]) ^ triple.c[i]);
    } finally {
      triple.a.fill(0); triple.b.fill(0); triple.c.fill(0);
    }
  };
}
