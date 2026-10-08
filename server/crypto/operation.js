import { waitForReadExchange } from './read-round-store.js';
import { DPF_VALUE_BYTE } from './duoram-dpf.js';

export function shiftDpfEvaluation(evaluation, shift) {
  if (!Number.isInteger(shift) || shift < 0 || shift >= evaluation.flags.length) throw new TypeError('Invalid DPF shift');
  return {
    flags: evaluation.flags.map((_, index) => evaluation.flags[index ^ shift]),
    values: evaluation.values.map((_, index) => evaluation.values[index ^ shift]),
    finalCorrectionShare: evaluation.finalCorrectionShare,
  };
}

export async function runSharedBitOperation({ party, sessionId, operation, indexShareBits, valueShare,
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
  if (![0, 1].includes(cancellation.gamma) || cancellation.version !== blindVersion) throw new Error('Invalid helper cancellation');
  const readFlags = components[0].flags;
  const otherBlindFlags = components[party === 0 ? 2 : 1].flags;
  let readShare = cancellation.gamma, validityShare = 0;
  for (let i = 0; i < databaseShare.length; i++) {
    readShare ^= ((databaseShare[i] ^ peerBlindedShare[i]) & readFlags[i]) ^
      (blindShare[i] & (otherBlindFlags[i] ^ readFlags[i]));
    validityShare ^= readFlags[i];
  }
  if (operation === 'access') return { share: readShare, validityShare };

  const correctionShares = components.map(evaluation => {
    const word = Buffer.from(evaluation.finalCorrectionShare);
    word[DPF_VALUE_BYTE] ^= readShare ^ valueShare;
    return word.toString('hex');
  });
  const peer = await exchange('update', { correctionShares });
  if (!Array.isArray(peer?.correctionShares) || peer.correctionShares.length !== 3 ||
      peer.correctionShares.some(word => typeof word !== 'string' || !/^[0-9a-f]{32}$/.test(word))) throw new Error('Invalid value corrections');
  const corrections = correctionShares.map((encoded, c) => {
    const word = Buffer.from(encoded, 'hex'), other = Buffer.from(peer.correctionShares[c], 'hex');
    for (let byte = 0; byte < 16; byte++) word[byte] ^= other[byte];
    return word;
  });
  const deltas = components.map((evaluation, c) => databaseShare.map((_, i) =>
    (evaluation.values[i][DPF_VALUE_BYTE] & 1) ^ (evaluation.flags[i] & (corrections[c][DPF_VALUE_BYTE] & 1))));
  const ownBlindComponent = party === 0 ? 1 : 2;
  const peerBlindComponent = party === 0 ? 2 : 1;
  const staged = await helperRequest('/internal/stage-update', {
    id: sessionId, finalBlinds: corrections.slice(1).map(word => word.toString('hex')),
  });
  if (!staged.staged) throw new Error('Helper blind refresh was not staged');
  return {
    ok: true, validityShare,
    updatedDatabaseShare: databaseShare.map((bit, i) => bit ^ deltas[0][i]),
    updatedBlindShare: blindShare.map((bit, i) => bit ^ deltas[ownBlindComponent][i]),
    updatedPeerBlindedShare: peerBlindedShare.map((bit, i) => bit ^ deltas[0][i] ^ deltas[peerBlindComponent][i]),
  };
}
