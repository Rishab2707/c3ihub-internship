import { createHash, randomBytes } from 'node:crypto';
import { createExtensionReceiver, createExtensionSenderReply, finishExtensionReceiver } from './ot-extension.js';

// A deliberately simple Naor–Pinkas-style encrypted-download CSPIR.
// Full-domain downloads hide the query perfectly; the OT-selected keys make
// only one cell decryptable, under passive OT security and the SHA-256 ROM.
// This does not implement SPIRAL or its sublinear communication bound.
const KEY_BITS = 128;

export function bitsToIndex(bits) {
  return bits.reduce((index, bit, position) => index | (bit << position), 0);
}

function pad(context, index, keys) {
  const encodedIndex = Buffer.alloc(4);
  encodedIndex.writeUInt32LE(index);
  return createHash('sha256').update('DUORAM-CSPIR-PAD-v1\0')
    .update(context).update(encodedIndex).update(Buffer.concat(keys)).digest()[0] & 1;
}

export function prepareCspirReceiver(indexBits, receiverSeedPairs) {
  const choices = indexBits.flatMap(bit => Array(KEY_BITS).fill(bit));
  return createExtensionReceiver(receiverSeedPairs, choices);
}

export function prepareCspirSender({ request, domainBits, senderContext, context }) {
  if (request?.count !== domainBits * KEY_BITS) throw new TypeError('Invalid CSPIR OT query size');
  const pairs = Array.from({ length: domainBits }, () => [randomBytes(16), randomBytes(16)]);
  const messages = [0, 1].map(choice => pairs.flatMap(pair =>
    Array.from({ length: KEY_BITS }, (_, bit) => (pair[choice][bit >> 3] >> (bit & 7)) & 1)));
  const reply = createExtensionSenderReply(senderContext.selectedSeeds, senderContext.choices, request, messages[0], messages[1]);
  const pads = new Uint8Array(2 ** domainBits);
  for (let index = 0; index < pads.length; index++) {
    pads[index] = pad(context, index, pairs.map((pair, bit) => pair[(index >> bit) & 1]));
  }
  // Only encrypted OT alternatives leave the process; never the key pairs.
  return { reply, pads };
}

export function finishCspirReceiver({ state, reply, indexBits, context }) {
  const selected = finishExtensionReceiver(state, reply);
  if (selected.length !== indexBits.length * KEY_BITS) throw new TypeError('Invalid CSPIR selected keys');
  const keys = indexBits.map((_, bit) => {
    const key = Buffer.alloc(16);
    for (let position = 0; position < KEY_BITS; position++) {
      key[position >> 3] |= selected[bit * KEY_BITS + position] << (position & 7);
    }
    return key;
  });
  return pad(context, bitsToIndex(indexBits), keys);
}

export function encryptCspirResponse(databaseShare, pads, permutation, mask) {
  const packed = Buffer.alloc(Math.ceil(pads.length / 8));
  for (let index = 0; index < pads.length; index++) {
    const cell = databaseShare[index ^ permutation] ?? 0;
    packed[index >> 3] |= (cell ^ mask ^ pads[index]) << (index & 7);
  }
  return packed.toString('base64');
}

export function decryptCspirResponse(encoded, domainSize, index, selectedPad) {
  if (typeof encoded !== 'string') throw new TypeError('Invalid CSPIR response');
  const packed = Buffer.from(encoded, 'base64');
  if (packed.length !== Math.ceil(domainSize / 8) || packed.toString('base64') !== encoded) {
    throw new TypeError('Malformed CSPIR response');
  }
  return ((packed[index >> 3] >> (index & 7)) & 1) ^ selectedPad;
}
