import { waitForReadExchange } from './read-round-store.js';
import { createDuAtallahAndCallback } from './du-atallah.js';
import { BLOCK_BYTES, BLOCK_BITS, isBlockHex } from '../../shared/block-format.js';

export function shiftDpfEvaluation(evaluation, shift) {
  if (!Number.isInteger(shift) || shift < 0 || shift >= evaluation.flags.length) throw new TypeError('Invalid DPF shift');
  return {
    flags: evaluation.flags.map((_, index) => evaluation.flags[index ^ shift]),
    values: evaluation.values.map((_, index) => evaluation.values[index ^ shift]),
    finalCorrectionShare: evaluation.finalCorrectionShare,
  };
}

export async function runSharedBlockOperation({ party, sessionId, operation, indexShareBits, valueShare,
  databaseShare, blindShare, peerBlindedShare, blindVersion, preprocessing, peerRequest, helperRequest }) {
  if (party !== 0 && party !== 1) throw new TypeError('Invalid party');
  if (!['access', 'insert'].includes(operation) || !preprocessing?.consumed || preprocessing.party !== party) throw new Error('Reserved preprocessing is required');
  const exchange = party === 0
    ? (phase, contribution) => peerRequest('/internal/read/exchange', { sessionId, phase, contribution })
    : (phase, contribution) => waitForReadExchange(sessionId, phase, contribution);
  const toIndex = bits => bits.reduce((value, bit, position) => value | (bit << position), 0);
  const ownOffset = toIndex(indexShareBits) ^ toIndex(preprocessing.randomIndexBits);
  const { offset: peerOffset } = await exchange('offset', { offset: ownOffset });
  const domainSize = 2 ** preprocessing.domainBits;
  if (!Number.isInteger(peerOffset) || peerOffset < 0 || peerOffset >= domainSize) throw new TypeError('Invalid offset');
  const shift = ownOffset ^ peerOffset;
  const components = preprocessing.components.map(evaluation => shiftDpfEvaluation(evaluation, shift));
  const cancellation = await helperRequest('/internal/read', {
    id: sessionId, preprocessingId: preprocessing.id, shift, operation, version: blindVersion,
  });
  if (!isBlockHex(cancellation.gamma) || cancellation.version !== blindVersion) throw new Error('Invalid helper cancellation');
  const readFlags = components[0].flags;
  const otherBlindFlags = components[party === 0 ? 2 : 1].flags;
  const readShare = Buffer.from(cancellation.gamma, 'hex');
  const size = databaseShare.length / BLOCK_BYTES;
  let validityShare = 0;
  for (let i = 0; i < size; i++) {
    const readMask = -readFlags[i], blindMask = -(otherBlindFlags[i] ^ readFlags[i]);
    for (let byte = 0; byte < BLOCK_BYTES; byte++) {
      const offset = i * BLOCK_BYTES + byte;
      readShare[byte] ^= ((databaseShare[offset] ^ peerBlindedShare[offset]) & readMask) ^
        (blindShare[offset] & blindMask);
    }
    validityShare ^= readFlags[i];
  }
  if (operation === 'access') {
    preprocessing.writePool.discard();
    return { share: readShare.toString('hex'), validityShare };
  }

  // Secret conditional update: delta = (NOT occupied) AND (old XOR requested).
  // Keep occupancy hidden from A, B and the helper. No public rejection branch.
  const acceptedShare = (readShare[0] & 1) ^ Number(party === 0);
  const requested = Buffer.from(valueShare, 'hex');
  // Canonical occupied marker is enforced independently of the supplied shares.
  requested[0] = Number(party === 0);
  const operand = Array.from({ length: BLOCK_BITS }, (_, bit) =>
    ((readShare[bit >> 3] ^ requested[bit >> 3]) >> (bit & 7)) & 1);
  const andShares = createDuAtallahAndCallback({
    pool: preprocessing.writePool,
    exchangeOpenings: (_round, shares) => exchange('write-gate', shares),
  });
  const delta = Buffer.alloc(BLOCK_BYTES);
  try {
    const product = await andShares(Array(BLOCK_BITS).fill(acceptedShare), operand);
    for (let bit = 0; bit < BLOCK_BITS; bit++) delta[bit >> 3] |= product[bit] << (bit & 7);
    product.fill(0);
  } finally { preprocessing.writePool.discard(); operand.fill(0); requested.fill(0); }

  const correctionShares = components.map(evaluation => {
    const word = Buffer.from(evaluation.finalCorrectionShare);
    for (let byte = 0; byte < BLOCK_BYTES; byte++) word[byte] ^= delta[byte];
    return word.toString('hex');
  });
  delta.fill(0);
  const peer = await exchange('update', { correctionShares });
  if (!Array.isArray(peer?.correctionShares) || peer.correctionShares.length !== 3 ||
      !peer.correctionShares.every(isBlockHex)) throw new Error('Invalid value corrections');
  const corrections = correctionShares.map((encoded, c) => {
    const word = Buffer.from(encoded, 'hex'), other = Buffer.from(peer.correctionShares[c], 'hex');
    for (let byte = 0; byte < BLOCK_BYTES; byte++) word[byte] ^= other[byte];
    return word;
  });
  const deltas = components.map((evaluation, c) => {
    const result = new Uint8Array(databaseShare.length);
    for (let i = 0; i < size; i++) for (let byte = 0; byte < BLOCK_BYTES; byte++) {
      result[i * BLOCK_BYTES + byte] = evaluation.values[i][byte] ^ (-evaluation.flags[i] & corrections[c][byte]);
    }
    return result;
  });
  const ownBlindComponent = party === 0 ? 1 : 2;
  const peerBlindComponent = party === 0 ? 2 : 1;
  const staged = await helperRequest('/internal/stage-update', {
    id: sessionId, finalBlinds: corrections.slice(1).map(word => word.toString('hex')),
  });
  if (!staged.staged) throw new Error('Helper blind refresh was not staged');
  return {
    ok: true, validityShare, acceptedShare,
    updatedDatabaseShare: databaseShare.map((byte, i) => byte ^ deltas[0][i]),
    updatedBlindShare: blindShare.map((byte, i) => byte ^ deltas[ownBlindComponent][i]),
    updatedPeerBlindedShare: peerBlindedShare.map((byte, i) => byte ^ deltas[0][i] ^ deltas[peerBlindComponent][i]),
  };
}
