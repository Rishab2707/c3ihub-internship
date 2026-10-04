import { randomBytes } from 'node:crypto';

function assertBits(values, name) {
  if (!Array.isArray(values)) throw new TypeError(`${name} must be an array of bits`);
  let invalid = 0;
  for (const value of values) invalid |= Number(value !== 0) & Number(value !== 1);
  if (invalid !== 0) throw new TypeError(`${name} must be an array of bits`);
}

function randomBits(length) {
  const bytes = randomBytes(length);
  return Array.from(bytes, byte => byte & 1);
}

// One party's first-round work for bitwise multiplication of XOR shares.
// Complete each direction with base-ot.js, then call finishAndShares on both sides.
export function prepareAndShares(xShare, yShare) {
  assertBits(xShare, 'xShare');
  assertBits(yShare, 'yShare');
  if (xShare.length !== yShare.length) throw new RangeError('Share vectors must have equal length');
  const masks = randomBits(xShare.length);
  return {
    localProducts: xShare.map((x, i) => x & yShare[i]),
    masks,
    senderMessages0: masks,
    senderMessages1: xShare.map((x, i) => x ^ masks[i]),
    receiverChoices: yShare,
  };
}

// receivedFromPeer is the peer's OT receiver output for the peer's x-share
// multiplied by this party's y-share.
export function finishAndShare(prepared, receivedFromPeer) {
  const n = prepared?.localProducts?.length;
  assertBits(receivedFromPeer, 'receivedFromPeer');
  if (receivedFromPeer.length !== n) throw new RangeError('OT result length does not match');
  return prepared.localProducts.map((local, i) => local ^ receivedFromPeer[i] ^ prepared.masks[i]);
}
