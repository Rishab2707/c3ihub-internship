// Shared wire format: one occupied byte, one length byte, then ASCII and zero padding.
export const BLOCK_BYTES = 128;
export const BLOCK_BITS = BLOCK_BYTES * 8;
export const MAX_TEXT_BYTES = BLOCK_BYTES - 2;
export const DEFAULT_DB_SIZE = 1024;
export const ZERO_BLOCK_HEX = '00'.repeat(BLOCK_BYTES);

export function isBlockHex(value) {
  return typeof value === 'string' && /^[0-9a-f]+$/.test(value) && value.length === BLOCK_BYTES * 2;
}

export function blockToHex(bytes) {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

export function blockFromHex(value) {
  if (!isBlockHex(value)) throw new TypeError('Expected a fixed-size hexadecimal block share');
  return Uint8Array.from({ length: BLOCK_BYTES }, (_, i) => parseInt(value.slice(i * 2, i * 2 + 2), 16));
}

export function encodeTextBlock(text) {
  if (typeof text !== 'string' || text.length > MAX_TEXT_BYTES || /[^\x00-\x7f]/.test(text)) {
    throw new TypeError(`Use at most ${MAX_TEXT_BYTES} ASCII characters`);
  }
  const block = new Uint8Array(BLOCK_BYTES);
  block[0] = 1;
  block[1] = text.length;
  for (let i = 0; i < text.length; i++) block[i + 2] = text.charCodeAt(i);
  return block;
}

export function decodeTextBlock(block) {
  if (!(block instanceof Uint8Array) || block.length !== BLOCK_BYTES || block[0] > 1 || block[1] > MAX_TEXT_BYTES) {
    throw new TypeError('Invalid text block');
  }
  if (!block[0]) {
    if (block.some(byte => byte !== 0)) throw new TypeError('Invalid empty block');
    return { occupied: false, text: '' };
  }
  const payload = block.subarray(2, 2 + block[1]);
  if (payload.some(byte => byte > 127) || block.subarray(2 + block[1]).some(byte => byte !== 0)) throw new TypeError('Invalid ASCII block');
  return { occupied: true, text: String.fromCharCode(...payload) };
}
