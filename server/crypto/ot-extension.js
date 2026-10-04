import { createCipheriv, createHash, createHmac, randomBytes } from 'node:crypto';
import { createReceiver, createSender, createSenderReplyBytes, finishReceiverBytes } from './base-ot.js';

const SECURITY = 128;
const MAX_EXTENDED_OTS = 1_000_000;
const ROW_BYTES = SECURITY / 8;

export function createExtensionReceiverBaseOffer(context) {
  const seedPairs = Array.from({ length: SECURITY }, () => [randomBytes(16).toString('hex'), randomBytes(16).toString('hex')]);
  const offer = createSender(SECURITY, context);
  return { state: { offerState: offer.state, seedPairs }, message: offer.message };
}

export function finishExtensionReceiverBaseOffer(state, publicB) {
  if (!Array.isArray(state?.seedPairs) || state.seedPairs.length !== SECURITY) throw new TypeError('Invalid extension receiver base-OT state');
  const reply = createSenderReplyBytes(state.offerState, publicB, state.seedPairs.map(pair => pair[0]), state.seedPairs.map(pair => pair[1]));
  return { state: { seedPairs: state.seedPairs }, message: reply };
}

export function createExtensionSenderBaseReply(publicA, context) {
  if (!Array.isArray(publicA) || publicA.length !== SECURITY) throw new TypeError(`Need ${SECURITY} base OT public keys`);
  const choices = Array.from(randomBytes(SECURITY), byte => byte & 1);
  const receiver = createReceiver(publicA, choices, context);
  return { state: { choices, receiverState: receiver.state }, message: receiver.message };
}

export function finishExtensionSenderBaseReply(state, ciphertexts) {
  if (!Array.isArray(state?.choices) || state.choices.length !== SECURITY) throw new TypeError('Invalid extension sender base-OT state');
  const selectedSeeds = finishReceiverBytes(state.receiverState, ciphertexts);
  return { choices: state.choices, selectedSeeds };
}

function assertCount(count) {
  if (!Number.isSafeInteger(count) || count < 0 || count > MAX_EXTENDED_OTS) {
    throw new RangeError(`Extended OT count must be between 0 and ${MAX_EXTENDED_OTS}`);
  }
}

function assertBits(values, name, expectedLength) {
  if (!Array.isArray(values) || (expectedLength !== undefined && values.length !== expectedLength)) {
    throw new TypeError(`${name} must be an array of ${expectedLength ?? '0 or more'} bits`);
  }
  let invalid = 0;
  for (const bit of values) invalid |= Number(bit !== 0) & Number(bit !== 1);
  if (invalid !== 0) throw new TypeError(`${name} must be an array of ${expectedLength ?? '0 or more'} bits`);
}

function decodeSeed(seed) {
  if (typeof seed !== 'string' || !/^[0-9a-f]{32}$/i.test(seed)) throw new TypeError('OT extension seeds must be 16-byte hex strings');
  return Buffer.from(seed, 'hex');
}

function packBits(bits) {
  const packed = Buffer.alloc(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i++) packed[i >> 3] |= bits[i] << (i & 7);
  return packed;
}

function getBit(packed, index) {
  return (packed[index >> 3] >> (index & 7)) & 1;
}

function xorInto(target, source) {
  for (let i = 0; i < target.length; i++) target[i] ^= source[i];
  return target;
}

function xorMaskedInto(target, source, bit) {
  const mask = -bit;
  for (let i = 0; i < target.length; i++) target[i] ^= source[i] & mask;
  return target;
}

function expand(seed, sessionId, row, count) {
  const rowKey = createHmac('sha256', seed)
    .update('DUORAM-IKNP-ROW-v3')
    .update(Buffer.from([row]))
    .update(sessionId)
    .digest()
    .subarray(0, 16);
  // A distinct PRF-derived key for every row and batch prevents overlapping
  // CTR ranges across different session IDs from reusing keystream. The
  // counter starts at zero and stays below 7,813 blocks at the supported cap.
  // Repeating a session ID still repeats a stream: fresh 128-bit randomness
  // and the passive-party model remain required.
  const cipher = createCipheriv('aes-128-ctr', rowKey, Buffer.alloc(16));
  const zeros = Buffer.alloc(Math.ceil(count / 8));
  return Buffer.concat([cipher.update(zeros), cipher.final()]);
}

function columnBit(rows, index) {
  const column = Buffer.alloc(ROW_BYTES);
  for (let row = 0; row < SECURITY; row++) {
    column[row >> 3] |= getBit(rows[row], index) << (row & 7);
  }
  return column;
}

function columnHash(sessionId, index, column) {
  return createHash('sha256')
    .update('IKNP-OT-v2')
    .update(sessionId)
    .update(Buffer.from([index & 0xff, (index >>> 8) & 0xff, (index >>> 16) & 0xff, (index >>> 24) & 0xff]))
    .update(column)
    .digest()[0] & 1;
}

function parseRows(rows, count, name) {
  if (!Array.isArray(rows) || rows.length !== SECURITY) throw new TypeError(`${name} must contain ${SECURITY} rows`);
  const rowLength = Math.ceil(count / 8);
  const parsed = rows.map(row => {
    if (typeof row !== 'string') throw new TypeError(`${name} rows must be base64 strings`);
    const value = Buffer.from(row, 'base64');
    if (value.length !== rowLength || value.toString('base64') !== row) throw new TypeError(`Malformed ${name} row`);
    return value;
  });
  return parsed;
}

// IKNP extension receiver: the party holding OT choices. baseSeedPairs[i]
// contains the two random seeds delivered by 128 base OTs.
export function createExtensionReceiver(baseSeedPairs, choices) {
  if (!Array.isArray(choices)) throw new TypeError('choices must be an array');
  assertCount(choices.length);
  assertBits(choices, 'choices');
  if (!Array.isArray(baseSeedPairs) || baseSeedPairs.length !== SECURITY) throw new TypeError(`Need ${SECURITY} base OT seed pairs`);

  const sessionId = randomBytes(16);
  const choiceBits = packBits(choices);
  const tRows = [];
  const uRows = [];
  for (let row = 0; row < SECURITY; row++) {
    const pair = baseSeedPairs[row];
    if (!Array.isArray(pair) || pair.length !== 2) throw new TypeError('Each base OT must provide two seeds');
    const t = expand(decodeSeed(pair[0]), sessionId, row, choices.length);
    const t1 = expand(decodeSeed(pair[1]), sessionId, row, choices.length);
    const u = xorInto(t1, t);
    xorInto(u, choiceBits);
    tRows.push(t);
    uRows.push(u.toString('base64'));
  }
  return {
    state: { count: choices.length, sessionId: sessionId.toString('hex'), choices: choiceBits.toString('base64'), tRows: tRows.map(row => row.toString('base64')) },
    message: { count: choices.length, sessionId: sessionId.toString('hex'), uRows },
  };
}

// IKNP extension sender. baseSeeds are the selected seeds from the matching
// 128 base OTs, and baseChoices are the receiver's secret base-OT choice bits.
export function createExtensionSenderReply(baseSeeds, baseChoices, request, messages0, messages1) {
  const count = request?.count;
  assertCount(count);
  assertBits(baseChoices, 'baseChoices', SECURITY);
  if (!Array.isArray(baseSeeds) || baseSeeds.length !== SECURITY || !Array.isArray(messages0) ||
      !Array.isArray(messages1) || messages0.length !== count || messages1.length !== count) {
    throw new TypeError('Invalid OT extension sender inputs');
  }
  assertBits(messages0, 'messages0', count);
  assertBits(messages1, 'messages1', count);
  if (typeof request.sessionId !== 'string' || !/^[0-9a-f]{32}$/i.test(request.sessionId)) throw new TypeError('Malformed OT extension session id');
  const sessionId = Buffer.from(request.sessionId, 'hex');
  const uRows = parseRows(request.uRows, count, 'U');
  const qRows = [];
  for (let row = 0; row < SECURITY; row++) {
    const q = expand(decodeSeed(baseSeeds[row]), sessionId, row, count);
    xorMaskedInto(q, uRows[row], baseChoices[row]);
    qRows.push(q);
  }

  const c0 = Buffer.alloc(Math.ceil(count / 8));
  const c1 = Buffer.alloc(Math.ceil(count / 8));
  for (let index = 0; index < count; index++) {
    const qColumn = columnBit(qRows, index);
    const qXorS = Buffer.from(qColumn);
    for (let row = 0; row < SECURITY; row++) qXorS[row >> 3] ^= baseChoices[row] << (row & 7);
    const key0 = columnHash(sessionId, index, qColumn);
    const key1 = columnHash(sessionId, index, qXorS);
    c0[index >> 3] |= (messages0[index] ^ key0) << (index & 7);
    c1[index >> 3] |= (messages1[index] ^ key1) << (index & 7);
  }
  return { sessionId: request.sessionId, count, c0: c0.toString('base64'), c1: c1.toString('base64') };
}

export function finishExtensionReceiver(state, reply) {
  const count = reply?.count;
  assertCount(count);
  if (!state || !Number.isSafeInteger(state.count) || state.count !== count ||
      state.sessionId !== reply.sessionId || typeof state.choices !== 'string') {
    throw new TypeError('OT extension response does not match its request');
  }
  const sessionId = Buffer.from(state.sessionId, 'hex');
  const choices = Buffer.from(state.choices, 'base64');
  const tRows = parseRows(state.tRows, count, 'T');
  const c0 = Buffer.from(reply.c0 ?? '', 'base64');
  const c1 = Buffer.from(reply.c1 ?? '', 'base64');
  const expectedLength = Math.ceil(count / 8);
  if (c0.length !== expectedLength || c1.length !== expectedLength) throw new TypeError('Malformed OT extension ciphertexts');
  const output = [];
  for (let index = 0; index < count; index++) {
    const choice = getBit(choices, index);
    const key = columnHash(sessionId, index, columnBit(tRows, index));
    const selected = (getBit(c0, index) & (choice ^ 1)) | (getBit(c1, index) & choice);
    output.push(selected ^ key);
  }
  return output;
}
