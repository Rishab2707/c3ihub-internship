import { createCipheriv, randomBytes } from 'node:crypto';

const LABEL_BYTES = 16;
const LABEL_BITS = LABEL_BYTES * 8;
const KEY_VERSION = 3;
const PRG_KIND = 'aes128-fixed-key-davies-meyer-v1';
// Block128(high, low) in prg.cpp has little-endian low/high uint64 lanes.
// This is a public PRG parameter, not a server secret or an encryption key
// for database contents. Security assumes this fixed-key expansion is a PRG.
const PRG_KEY = Buffer.alloc(LABEL_BYTES);
PRG_KEY.writeBigUInt64LE(3602874713526624977n, 0);
PRG_KEY.writeBigUInt64LE(2718281828459045235n, 8);
// Byte zero's low bit belongs to the control output and is cleared in labels.
// Use a remaining seed bit for binary value masking and deferred corrections.
export const DPF_VALUE_BYTE = 1;

function assertBits(bits, name, length) {
  if (!Array.isArray(bits) || bits.length !== length) throw new TypeError(`${name} must contain ${length} bits`);
  let invalid = 0;
  for (const bit of bits) invalid |= Number(bit !== 0) & Number(bit !== 1);
  if (invalid !== 0) throw new TypeError(`${name} must contain ${length} bits`);
}

function xorWordInto(target, source) {
  for (let i = 0; i < LABEL_BYTES; i++) target[i] ^= source[i];
}

function expandLabel(label) {
  const { children, childFlags } = expandLayer([label]);
  return [children[0], children[1], childFlags[0], childFlags[1]];
}

function bitAt(word, bit) {
  return (word[bit >> 3] >> (bit & 7)) & 1;
}

function setBit(word, bit, value) {
  word[bit >> 3] |= value << (bit & 7);
}

function decodeWord(word) {
  if (typeof word !== 'string' || !/^[0-9a-f]{32}$/.test(word)) throw new TypeError('DPF words must be 16-byte hexadecimal strings');
  return Buffer.from(word, 'hex');
}

function correctChild(label, parentFlag, word) {
  const mask = -parentFlag;
  for (let byte = 0; byte < LABEL_BYTES; byte++) label[byte] ^= word[byte] & mask;
}

function advanceLayer(children, childFlags, flags, correction) {
  const word = decodeWord(correction.word);
  const nextFlags = new Uint8Array(children.length);
  for (let node = 0; node < flags.length; node++) {
    const left = node * 2, right = left + 1;
    // Flags use the PRG output BEFORE its label correction (Appendix C).
    nextFlags[left] = childFlags[left] ^ (flags[node] & correction.left);
    nextFlags[right] = childFlags[right] ^ (flags[node] & correction.right);
    correctChild(children[left], flags[node], word);
    correctChild(children[right], flags[node], word);
  }
  return nextFlags;
}

function expandLayer(labels) {
  const children = new Array(labels.length * 2);
  const childFlags = new Uint8Array(children.length);
  const inputs = Buffer.alloc(children.length * LABEL_BYTES);
  for (let node = 0; node < labels.length; node++) {
    const left = node * 2 * LABEL_BYTES, right = left + LABEL_BYTES;
    labels[node].copy(inputs, left);
    labels[node].copy(inputs, right);
    inputs[left] &= 0xfe;
    inputs[right] |= 1;
  }
  // Batch independent AES blocks into one OpenSSL call per tree layer.
  // ECB here is a raw block-cipher primitive, not database encryption.
  const cipher = createCipheriv('aes-128-ecb', PRG_KEY, null);
  cipher.setAutoPadding(false);
  const outputs = cipher.update(inputs);
  if (cipher.final().length !== 0 || outputs.length !== inputs.length) {
    throw new Error('Unexpected AES DPF expansion length');
  }
  for (let child = 0; child < children.length; child++) {
    const offset = child * LABEL_BYTES;
    const seed = Buffer.alloc(LABEL_BYTES);
    // G_b(s) = AES_K(s with LSB=b) XOR (s with LSB=b), as in prg.cpp.
    for (let byte = 0; byte < LABEL_BYTES; byte++) seed[byte] = outputs[offset + byte] ^ inputs[offset + byte];
    childFlags[child] = seed[0] & 1;
    seed[0] &= 0xfe;
    children[child] = seed;
  }
  return { children, childFlags };
}

// Joint 2-party DPF generation from XOR-shared target-index bits, following
// the tree-reduction method of Appendix C of DUORAM, with separate seed and
// control outputs as in BGI. A key contains a private root seed and O(log N)
// correction words. MPC computes only a 128-bit correction share per level;
// the combined correction word and controls are public DPF key material.
// exchangeControlShares(level, left, right, wordShare) exchanges these shares,
// never the index bits, seeds, labels, or flags.
export async function generateDuoramDpfShare({
  indexShareBits,
  domainBits,
  party,
  andShares,
  exchangeControlShares,
  onEvaluation,
}) {
  if (!Number.isInteger(domainBits) || domainBits < 1 || domainBits > 20) throw new RangeError('domainBits must be between 1 and 20');
  if (party !== 0 && party !== 1) throw new TypeError('party must be 0 or 1');
  assertBits(indexShareBits, 'indexShareBits', domainBits);
  if (typeof andShares !== 'function' || typeof exchangeControlShares !== 'function') {
    throw new TypeError('AND and control-exchange callbacks are required');
  }
  if (onEvaluation !== undefined && typeof onEvaluation !== 'function') throw new TypeError('onEvaluation must be a function');

  const root = randomBytes(LABEL_BYTES);
  root[0] = (root[0] & 0xfe) | party;
  let labels = [root];
  let flags = Uint8Array.of(party);
  const corrections = [];

  for (let level = 0; level < domainBits; level++) {
    const targetShare = indexShareBits[domainBits - level - 1];
    const { children, childFlags } = expandLayer(labels);

    const leftXor = Buffer.alloc(LABEL_BYTES), rightXor = Buffer.alloc(LABEL_BYTES);
    for (let child = 0; child < children.length; child += 2) {
      xorWordInto(leftXor, children[child]);
      xorWordInto(rightXor, children[child + 1]);
    }
    let localLeftControl = targetShare, localRightControl = targetShare;
    for (let child = 0; child < childFlags.length; child += 2) {
      localLeftControl ^= childFlags[child];
      localRightControl ^= childFlags[child + 1];
    }

    // cw = R0^R1 ^ ((alpha0^alpha1) & ((L0^R0)^(L1^R1))). The AND
    // callback returns XOR shares, so neither server materializes alpha.
    const altShare = Buffer.alloc(LABEL_BYTES);
    for (let i = 0; i < LABEL_BYTES; i++) altShare[i] = leftXor[i] ^ rightXor[i];
    const indexBits = new Array(LABEL_BITS).fill(targetShare);
    const altBits = Array.from({ length: LABEL_BITS }, (_, bit) => bitAt(altShare, bit));
    const productShare = await andShares(indexBits, altBits);
    assertBits(productShare, 'AND result share', LABEL_BITS);
    const correctionShare = Buffer.alloc(LABEL_BYTES);
    for (let bit = 0; bit < LABEL_BITS; bit++) setBit(correctionShare, bit, bitAt(rightXor, bit) ^ productShare[bit]);

    const peerControls = await exchangeControlShares(level, localLeftControl, localRightControl, correctionShare.toString('hex'));
    assertBits([peerControls?.left, peerControls?.right], 'peer correction controls', 2);
    const word = decodeWord(peerControls?.wordShare);
    xorWordInto(word, correctionShare);
    const correction = {
      word: word.toString('hex'),
      left: localLeftControl ^ peerControls.left ^ 1,
      right: localRightControl ^ peerControls.right,
    };
    corrections.push(correction);
    flags = advanceLayer(children, childFlags, flags, correction);
    labels = children;
  }

  // Joint generation already visits and corrects every leaf. Preprocessing
  // may retain these local leaves instead of repeating all PRG expansions.
  if (onEvaluation) onEvaluation(leafEvaluation(labels, flags));
  return { version: KEY_VERSION, kind: 'duoram-dpf', prg: PRG_KIND, party, domainBits, root: root.toString('hex'), corrections };
}

function leafEvaluation(labels, flags) {
  const finalCorrectionShare = Buffer.alloc(LABEL_BYTES);
  for (const label of labels) xorWordInto(finalCorrectionShare, label);
  return { flags, values: labels, finalCorrectionShare };
}

function validateKey(key) {
  if (!key || key.version !== KEY_VERSION || key.kind !== 'duoram-dpf' || key.prg !== PRG_KIND ||
      (key.party !== 0 && key.party !== 1) || !Number.isInteger(key.domainBits) ||
      key.domainBits < 1 || key.domainBits > 20 || !Array.isArray(key.corrections) || key.corrections.length !== key.domainBits) {
    throw new TypeError('Malformed DUORAM DPF key share');
  }
  const root = decodeWord(key.root);
  if ((root[0] & 1) !== key.party) throw new TypeError('Malformed AES DPF root control');
  for (const correction of key.corrections) {
    assertBits([correction?.left, correction?.right], 'DPF correction controls', 2);
    if ((decodeWord(correction?.word)[0] & 1) !== 0) throw new TypeError('DPF seed correction must exclude the control bit');
  }
  return root;
}

// Full-domain local evaluation for oblivious database scans.
export function evaluateDuoramDpfShare(key) {
  return evaluateDuoramDpfValues(key).flags;
}

// Corresponds to DPF::evaluate_full_values in cpp-implementation/dpf.cpp.
// Retain the leaf labels for DUORAM's deferred update correction.
export function evaluateDuoramDpfValues(key) {
  let labels = [validateKey(key)];
  let flags = Uint8Array.of(key.party);
  for (let level = 0; level < key.domainBits; level++) {
    const { children, childFlags } = expandLayer(labels);
    flags = advanceLayer(children, childFlags, flags, key.corrections[level]);
    labels = children;
  }
  return leafEvaluation(labels, flags);
}

// Point evaluation traverses one path in O(log N), without expanding the tree.
export function evaluateDuoramDpfAt(key, index) {
  let label = validateKey(key), flag = key.party;
  if (!Number.isSafeInteger(index) || index < 0 || index >= 2 ** key.domainBits) throw new RangeError('Index is outside the DPF domain');
  for (let level = 0; level < key.domainBits; level++) {
    const branch = (index >>> (key.domainBits - level - 1)) & 1;
    const children = expandLabel(label);
    const correction = key.corrections[level];
    label = children[branch];
    const nextFlag = children[branch + 2] ^ (flag & (branch === 0 ? correction.left : correction.right));
    correctChild(label, flag, decodeWord(correction.word));
    flag = nextFlag;
  }
  return flag;
}
