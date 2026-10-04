const controls = new Map();
const MAX_PENDING_CONTROLS = 128;
const CONTROL_TIMEOUT_MS = 120_000;

function validate(sessionId, level) {
  if (typeof sessionId !== 'string' || !/^[0-9a-f-]{16,64}$/i.test(sessionId)) throw new TypeError('Invalid DPF control session id');
  // Levels 0..d-1 generate the tree; level d carries a write's deferred CW.
  if (!Number.isSafeInteger(level) || level < 0 || level > 20) throw new TypeError('Invalid DPF control level');
  return `${sessionId}:${level}`;
}

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  // A peer may time out before the matching side registers its waiter.
  // Mark the rejection handled at creation while preserving rejection for
  // any later caller that awaits this promise.
  promise.catch(() => {});
  return { promise, resolve, reject };
}

function getEntry(key) {
  let entry = controls.get(key);
  if (entry) return entry;
  if (controls.size >= MAX_PENDING_CONTROLS) throw new Error('Too many pending DPF control exchanges');
  entry = { ready: deferred(), peer: deferred(), local: null, timer: null };
  entry.timer = setTimeout(() => {
    controls.delete(key);
    const error = new Error('DPF control exchange timed out');
    entry.ready.reject(error);
    entry.peer.reject(error);
  }, CONTROL_TIMEOUT_MS);
  entry.timer.unref?.();
  controls.set(key, entry);
  return entry;
}

function bit(value) { return value === 0 || value === 1; }

function validateContribution(left, right, wordShare) {
  if (!bit(left) || !bit(right) || typeof wordShare !== 'string' || !/^[0-9a-f]{32}$/.test(wordShare)) {
    throw new TypeError('DPF contribution must contain two control bits and a 16-byte correction share');
  }
}

// Party B registers its masked controls first; it receives party A's values
// when A's authenticated internal request arrives.
export function waitForDpfControl(sessionId, level, left, right, wordShare) {
  const key = validate(sessionId, level);
  validateContribution(left, right, wordShare);
  const entry = getEntry(key);
  if (entry.local) throw new Error('Duplicate local DPF control registration');
  entry.local = { left, right, wordShare };
  entry.ready.resolve();
  return entry.peer.promise.finally(() => {
    clearTimeout(entry.timer);
    controls.delete(key);
  });
}

// Party A sends its masked controls and receives B's matching contribution.
export async function exchangeDpfControl(sessionId, level, left, right, wordShare) {
  const key = validate(sessionId, level);
  validateContribution(left, right, wordShare);
  const entry = getEntry(key);
  await entry.ready.promise;
  if (entry.peerReceived) throw new Error('Duplicate peer DPF control exchange');
  entry.peerReceived = true;
  entry.peer.resolve({ left, right, wordShare });
  const local = entry.local;
  clearTimeout(entry.timer);
  controls.delete(key);
  return local;
}
