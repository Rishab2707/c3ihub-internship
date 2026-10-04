// Chou-Orlandi base 1-out-of-2 OT over the RFC 3526 group 15 subgroup.
// This is an online, semi-honest primitive; the production validation gate
// stays closed while its concrete security assumptions remain unreviewed.
import { createDiffieHellman, createHash, getDiffieHellman, randomBytes } from 'node:crypto';

const MODP_GROUP = 'modp15'; // RFC 3526 3072-bit safe prime.
const dh = getDiffieHellman(MODP_GROUP);
const P = BigInt(`0x${dh.getPrime('hex')}`);
const Q = (P - 1n) / 2n;
const WIDTH = Math.ceil(dh.getPrime().length);
const MAX_OTS = 250_000;
const EXPONENT_LIMIT = Buffer.from(Q.toString(16).padStart(WIDTH * 2, '0'), 'hex');
let privateEngine;

function sampleExponent() {
  // Q has 3071 bits. Rejection, rather than reduction modulo Q, gives an
  // exactly uniform nonzero exponent. Compare fixed-width byte strings so
  // the sampler never converts the private exponent to a JavaScript BigInt.
  for (;;) {
    const exponent = randomBytes(WIDTH);
    exponent[0] &= 0x7f;
    let nonzero = 0;
    for (const byte of exponent) nonzero |= byte;
    if (nonzero !== 0 && Buffer.compare(exponent, EXPONENT_LIMIT) < 0) return exponent;
    exponent.fill(0);
  }
}

function engineFor(privateKey) {
  // Group verification in createDiffieHellman is expensive. Cache only the
  // native arithmetic engine; each OT agreement owns its own private buffer.
  // These calls and their callers are synchronous: setPrivateKey and the
  // following native operation cannot interleave with another agreement.
  if (!privateEngine) privateEngine = createDiffieHellman(dh.getPrime(), dh.getGenerator());
  privateEngine.setPrivateKey(privateKey);
  return privateEngine;
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  let value = base % modulus;
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) result = result * value % modulus;
    value = value * value % modulus;
    power >>= 1n;
  }
  return result;
}

function modInverse(value, modulus) {
  let oldR = modulus, r = value % modulus;
  let oldS = 0n, s = 1n;
  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
  }
  if (oldR !== 1n) throw new RangeError('OT group element has no inverse');
  return (oldS % modulus + modulus) % modulus;
}

function encode(value) {
  return value.toString(16).padStart(WIDTH * 2, '0');
}

function createAgreement() {
  // Sample the full subgroup explicitly and let OpenSSL perform secret
  // exponentiation. Do not rely on a runtime-selected short DH exponent.
  // JavaScript BigInt modular exponentiation is variable-time and must not be
  // used for the private operations in base OT. The RFC 3526 generator has
  // order q for this group, so generated public keys remain in its checked
  // prime-order subgroup.
  const privateKey = sampleExponent();
  const publicKey = BigInt(`0x${engineFor(privateKey).generateKeys('hex')}`);
  const agreement = {
    computeSecret(publicElement) {
      return engineFor(privateKey).computeSecret(publicElement);
    },
  };
  if (modPow(publicKey, Q, P) !== 1n) throw new Error('OpenSSL generated an OT key outside the expected subgroup');
  return { agreement, publicKey };
}

function decode(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]+$/i.test(value) || value.length > WIDTH * 2) {
    throw new TypeError('Malformed OT group element');
  }
  const decoded = BigInt(`0x${value}`);
  if (decoded <= 1n || decoded >= P || modPow(decoded, Q, P) !== 1n) {
    throw new TypeError('OT group element is outside the prime-order subgroup');
  }
  return decoded;
}

function validateContext(context) {
  if (typeof context !== 'string' || context.length < 1 || Buffer.byteLength(context, 'utf8') > 256) {
    throw new TypeError('OT context must be a non-empty string of at most 256 bytes');
  }
  return context;
}

function deriveBytes(sharedSecret, a, b, index, context) {
  const contextBytes = Buffer.from(validateContext(context), 'utf8');
  const indexBytes = Buffer.alloc(4);
  indexBytes.writeUInt32BE(index);
  if (!Buffer.isBuffer(sharedSecret) || sharedSecret.length > WIDTH) throw new TypeError('Invalid DH shared secret');
  const encodedSecret = Buffer.alloc(WIDTH);
  sharedSecret.copy(encodedSecret, WIDTH - sharedSecret.length);
  // Hash the fixed-width group element and transcript, matching the hashed
  // DH/random-oracle formulation of passive OT. DH-keyed HMAC would need a
  // separate assumption about keys drawn from the subgroup distribution.
  return createHash('sha256')
    .update('DUORAM-CO-OT-v4')
    .update(Buffer.from([contextBytes.length >> 8, contextBytes.length & 0xff]))
    .update(contextBytes)
    .update(indexBytes)
    .update(Buffer.from(encode(a), 'hex'))
    .update(Buffer.from(encode(b), 'hex'))
    .update(encodedSecret)
    .digest();
}

function decodePayload(payload) {
  if (typeof payload !== 'string' || !/^(?:[0-9a-f]{2})*$/i.test(payload)) throw new TypeError('Malformed OT payload');
  return Buffer.from(payload, 'hex');
}

function xorPayload(payload, key) {
  if (payload.length > key.length) throw new RangeError('OT payload exceeds the base OT mask');
  const result = Buffer.alloc(payload.length);
  for (let i = 0; i < payload.length; i++) result[i] = payload[i] ^ key[i];
  return result;
}

function checkCount(count) {
  if (!Number.isSafeInteger(count) || count < 0 || count > MAX_OTS) {
    throw new RangeError(`OT count must be between 0 and ${MAX_OTS}`);
  }
}

export function createSender(count, context) {
  checkCount(count);
  validateContext(context);
  const agreements = [];
  const publicA = [];
  for (let i = 0; i < count; i++) {
    const { agreement, publicKey } = createAgreement();
    agreements.push(agreement);
    publicA.push(encode(publicKey));
  }
  return { state: { agreements, publicA, context }, message: { publicA } };
}

export function createReceiver(publicA, choices, context) {
  if (!Array.isArray(publicA) || !Array.isArray(choices) || publicA.length !== choices.length) {
    throw new TypeError('OT public keys and choices must be equal-length arrays');
  }
  checkCount(choices.length);
  validateContext(context);
  const receiverState = [];
  const publicB = [];
  for (let i = 0; i < choices.length; i++) {
    const A = decode(publicA[i]);
    const choice = choices[i];
    const invalidChoice = Number(choice !== 0) & Number(choice !== 1);
    if (invalidChoice !== 0) throw new TypeError('OT choices must be bits');
    const { agreement, publicKey } = createAgreement();
    const gb = publicKey;
    const b1 = A * gb % P;
    const choiceMask = -BigInt(choice);
    const B = (gb & ~choiceMask) | (b1 & choiceMask);
    receiverState.push({ agreement, A: encode(A), B: encode(B), choice, context });
    publicB.push(encode(B));
  }
  return { state: receiverState, message: { publicB } };
}

export function createSenderReply(state, publicB, messages0, messages1) {
  const count = state?.agreements?.length;
  if (!Number.isSafeInteger(count) || !Array.isArray(publicB) || publicB.length !== count ||
      !Array.isArray(messages0) || !Array.isArray(messages1) || messages0.length !== count || messages1.length !== count) {
    throw new TypeError('Invalid OT sender state or message lengths');
  }
  checkCount(count);
  const ciphertexts = [];
  for (let i = 0; i < count; i++) {
    const m0 = messages0[i], m1 = messages1[i];
    if ((m0 !== 0 && m0 !== 1) || (m1 !== 0 && m1 !== 1)) throw new TypeError('This OT implementation transfers single bits');
    const agreement = state.agreements[i];
    const A = decode(state.publicA?.[i]);
    const B = decode(publicB[i]);
    const shared0 = agreement.computeSecret(Buffer.from(encode(B), 'hex'));
    const shared1Point = B * modInverse(A, P) % P;
    const shared1 = agreement.computeSecret(Buffer.from(encode(shared1Point), 'hex'));
    ciphertexts.push([
      m0 ^ (deriveBytes(shared0, A, B, i, state.context)[0] & 1),
      m1 ^ (deriveBytes(shared1, A, B, i, state.context)[0] & 1),
    ]);
  }
  return { ciphertexts };
}

export function finishReceiver(state, ciphertexts) {
  if (!Array.isArray(state) || !Array.isArray(ciphertexts) || state.length !== ciphertexts.length) {
    throw new TypeError('Invalid OT receiver state or ciphertext lengths');
  }
  checkCount(state.length);
  const outputs = [];
  for (let i = 0; i < state.length; i++) {
    const item = state[i];
    const ciphertextPair = ciphertexts[i];
    if (!Array.isArray(ciphertextPair) || ciphertextPair.length !== 2 || ciphertextPair.some(bit => bit !== 0 && bit !== 1)) {
      throw new TypeError('Malformed OT ciphertext');
    }
    const A = decode(item.A), B = decode(item.B);
    const shared = item.agreement.computeSecret(Buffer.from(encode(A), 'hex'));
    const selected = (ciphertextPair[0] & (item.choice ^ 1)) | (ciphertextPair[1] & item.choice);
    outputs.push(selected ^ (deriveBytes(shared, A, B, i, item.context)[0] & 1));
  }
  return outputs;
}

// Base OT byte transfer for seeding OT extension. Payloads are capped at 32
// bytes by SHA-256 key derivation; extension seeds use 16 bytes.
export function createSenderReplyBytes(state, publicB, messages0, messages1) {
  const count = state?.agreements?.length;
  if (!Number.isSafeInteger(count) || !Array.isArray(publicB) || publicB.length !== count ||
      !Array.isArray(messages0) || !Array.isArray(messages1) || messages0.length !== count || messages1.length !== count) {
    throw new TypeError('Invalid OT sender state or payload lengths');
  }
  checkCount(count);
  const ciphertexts = [];
  for (let i = 0; i < count; i++) {
    const m0 = decodePayload(messages0[i]), m1 = decodePayload(messages1[i]);
    if (m0.length !== m1.length || m0.length > 32) throw new RangeError('Base OT payloads must be equal length and at most 32 bytes');
    const agreement = state.agreements[i];
    const A = decode(state.publicA?.[i]);
    const B = decode(publicB[i]);
    const shared0 = agreement.computeSecret(Buffer.from(encode(B), 'hex'));
    const shared1Point = B * modInverse(A, P) % P;
    const shared1 = agreement.computeSecret(Buffer.from(encode(shared1Point), 'hex'));
    ciphertexts.push([
      xorPayload(m0, deriveBytes(shared0, A, B, i, state.context)).toString('hex'),
      xorPayload(m1, deriveBytes(shared1, A, B, i, state.context)).toString('hex'),
    ]);
  }
  return { ciphertexts };
}

export function finishReceiverBytes(state, ciphertexts) {
  if (!Array.isArray(state) || !Array.isArray(ciphertexts) || state.length !== ciphertexts.length) {
    throw new TypeError('Invalid OT receiver state or ciphertext lengths');
  }
  checkCount(state.length);
  const outputs = [];
  for (let i = 0; i < state.length; i++) {
    const item = state[i], pair = ciphertexts[i];
    if (!Array.isArray(pair) || pair.length !== 2) throw new TypeError('Malformed OT ciphertext pair');
    const ciphertext0 = decodePayload(pair[0]), ciphertext1 = decodePayload(pair[1]);
    if (ciphertext0.length !== ciphertext1.length) throw new TypeError('OT ciphertext lengths do not match');
    const A = decode(item.A), B = decode(item.B);
    const shared = item.agreement.computeSecret(Buffer.from(encode(A), 'hex'));
    const mask = -item.choice;
    const selected = Buffer.alloc(ciphertext0.length);
    for (let j = 0; j < selected.length; j++) {
      selected[j] = (ciphertext0[j] & ~mask) | (ciphertext1[j] & mask);
    }
    outputs.push(xorPayload(selected, deriveBytes(shared, A, B, i, item.context)).toString('hex'));
  }
  return outputs;
}

