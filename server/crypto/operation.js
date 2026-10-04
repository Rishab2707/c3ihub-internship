import { randomBytes } from 'node:crypto';
import { waitForDpfControl } from './dpf-control-store.js';
import { bitsToIndex, encryptCspirResponse, decryptCspirResponse } from './cspir.js';
import { waitForReadExchange } from './read-round-store.js';

export function shiftDpfEvaluation(evaluation, shift) {
  if (!Number.isInteger(shift) || shift < 0 || shift >= evaluation.flags.length) throw new TypeError('Invalid DPF shift');
  return {
    flags: evaluation.flags.map((_, index) => evaluation.flags[index ^ shift]),
    values: evaluation.values.map((_, index) => evaluation.values[index ^ shift]),
    finalCorrectionShare: evaluation.finalCorrectionShare,
  };
}

async function applyPointOperation({ operation, evaluation, valueShare, databaseShare, readShare, exchangeControlShares, domainBits }) {
  if (operation !== 'access' && operation !== 'insert') throw new TypeError('Unsupported operation');
  const pointShare = evaluation.flags;
  // The XOR of the in-range point-function shares is a secret share of one
  // exactly when the addressed point has a backing database cell. Returning
  // this bit to the caller lets it reject padded-domain indices without
  // opening or reconstructing the address at either server.
  const validityShare = pointShare
    .slice(0, databaseShare.length)
    .reduce((valid, bit) => valid ^ bit, 0);
  if (operation === 'access') {
    return {
      share: readShare,
      validityShare,
    };
  }
  // A replacement first reads a shared old bit and converts the requested
  // new value into an XOR-shared delta. No party opens the old bit or delta.
  const oldBitShare = readShare;
  const correctionShare = Buffer.from(evaluation.finalCorrectionShare);
  correctionShare[0] ^= oldBitShare ^ valueShare;
  // The final exchange is separate from the d tree-level exchanges. This
  // opens only the deferred DPF correction, as in corrected_update_vector
  // in the C++ reference. It never opens the shared value or address.
  const peer = await exchangeControlShares(domainBits, 0, 0, correctionShare.toString('hex'));
  if (peer?.left !== 0 || peer?.right !== 0 || typeof peer.wordShare !== 'string' || !/^[0-9a-f]{32}$/.test(peer.wordShare)) {
    throw new TypeError('Invalid deferred DPF correction contribution');
  }
  const peerWord = Buffer.from(peer.wordShare, 'hex');
  for (let byte = 0; byte < correctionShare.length; byte++) correctionShare[byte] ^= peerWord[byte];
  // Binary storage is the low-bit projection of the reference's 128-bit
  // value-DPF update. All public positions are traversed on both parties.
  const updated = databaseShare.map((bit, index) => bit ^
    (evaluation.values[index][0] & 1) ^ (pointShare[index] & (correctionShare[0] & 1)));
  // Keep the share staged until the coordinator has confirmed that both
  // parties completed the MPC operation. The server commits it afterward.
  return { ok: true, validityShare, updatedDatabaseShare: updated };
}

export async function runSharedBitOperation({
  party,
  sessionId,
  operation,
  indexShareBits,
  valueShare,
  databaseShare,
  preprocessing,
  peerRequest,
}) {
  if (party !== 0 && party !== 1) throw new TypeError('party must be 0 or 1');
  if (!preprocessing?.consumed || preprocessing.party !== party) throw new Error('Reserved preprocessing is required');
  const exchange = party === 0
    ? (phase, contribution) => peerRequest('/internal/read/exchange', { sessionId, phase, contribution })
    : (phase, contribution) => waitForReadExchange(sessionId, phase, contribution);
  const ownIndexShare = bitsToIndex(indexShareBits);
  const randomIndex = bitsToIndex(preprocessing.randomIndexBits);
  const ownOffset = ownIndexShare ^ randomIndex;
  const { offset: peerOffset } = await exchange('offset', { offset: ownOffset });
  const domainSize = 2 ** preprocessing.domainBits;
  if (!Number.isInteger(peerOffset) || peerOffset < 0 || peerOffset >= domainSize) throw new TypeError('Invalid read offset');
  const evaluation = shiftDpfEvaluation(preprocessing.evaluation, ownOffset ^ peerOffset);
  // XOR-domain adaptation of DUORAM section 5: the peer's random query
  // selects D[alpha_own XOR alpha_peer] XOR ownMask, without opening alpha.
  const ownMask = randomBytes(1)[0] & 1;
  const ciphertext = encryptCspirResponse(databaseShare, preprocessing.pads, ownIndexShare ^ peerOffset, ownMask);
  const peerResponse = await exchange('response', { ciphertext });
  const maskedPeerBit = decryptCspirResponse(peerResponse.ciphertext, domainSize, randomIndex, preprocessing.selectedPad);
  const readShare = maskedPeerBit ^ ownMask;
  const exchangeControlShares = party === 0
    ? (level, left, right, wordShare) => peerRequest('/internal/mpc/dpf/control', { sessionId, level, left, right, wordShare })
    : (level, left, right, wordShare) => waitForDpfControl(sessionId, level, left, right, wordShare);
  return applyPointOperation({ operation, evaluation, valueShare, databaseShare, readShare,
    exchangeControlShares, domainBits: preprocessing.domainBits });
}

