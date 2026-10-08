import { randomBytes } from 'node:crypto';

function assertBits(bits, length) {
  if (!Array.isArray(bits) || bits.length !== length || bits.some(bit => bit !== 0 && bit !== 1)) {
    throw new TypeError('Expected a matching vector of bits');
  }
}

// Dealer-free Boolean Beaver triples. OT multiplies random shares only;
// actual DPF operands are never inputs to this OT batch.
export async function generateOtTriplePool(count, otMultiply) {
  if (!Number.isInteger(count) || count < 1 || count > 2560 || typeof otMultiply !== 'function') {
    throw new TypeError('Invalid triple batch');
  }
  const a = Array.from(randomBytes(count), byte => byte & 1);
  const b = Array.from(randomBytes(count), byte => byte & 1);
  let c;
  try {
    c = await otMultiply(a, b);
    assertBits(c, count);
  } catch (error) {
    a.fill(0); b.fill(0);
    throw error;
  }
  return createTriplePool(a, b, c);
}

export function createTriplePool(a, b, c) {
  const count = a?.length;
  if (!Number.isInteger(count) || count < 1 || count > 2560) throw new TypeError('Invalid triple batch');
  assertBits(a, count); assertBits(b, count); assertBits(c, count);
  let cursor = 0;
  return {
    get remaining() { return count - cursor; },
    take(length) {
      if (!Number.isInteger(length) || length < 1 || cursor + length > count) throw new Error('Fresh multiplication triples exhausted');
      const start = cursor;
      cursor += length; // Burn before any masked operand is opened.
      const batch = { a: a.slice(start, cursor), b: b.slice(start, cursor), c: c.slice(start, cursor) };
      a.fill(0, start, cursor); b.fill(0, start, cursor); c.fill(0, start, cursor);
      return batch;
    },
    discard() { a.fill(0); b.fill(0); c.fill(0); cursor = count; },
  };
}

export function createTripleAndCallback({ party, pool, exchangeOpenings }) {
  if ((party !== 0 && party !== 1) || !pool || typeof exchangeOpenings !== 'function') throw new TypeError('Invalid triple multiplication context');
  let roundId = 0;
  return async (x, y) => {
    assertBits(x, x?.length);
    assertBits(y, x.length);
    const triple = pool.take(x.length);
    const id = roundId++;
    try {
      const dShare = x.map((bit, i) => bit ^ triple.a[i]);
      const eShare = y.map((bit, i) => bit ^ triple.b[i]);
      const peer = await exchangeOpenings(id, { dShare, eShare });
      assertBits(peer?.dShare, x.length); assertBits(peer?.eShare, x.length);
      return x.map((_, i) => {
        const d = dShare[i] ^ peer.dShare[i], e = eShare[i] ^ peer.eShare[i];
        // Public d*e is assigned to exactly one party's XOR output share.
        return triple.c[i] ^ (d & triple.b[i]) ^ (e & triple.a[i]) ^ ((party ^ 1) & d & e);
      });
    } finally {
      triple.a.fill(0); triple.b.fill(0); triple.c.fill(0);
    }
  };
}
