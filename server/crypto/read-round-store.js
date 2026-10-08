const rounds = new Map();
const timeoutMs = 120_000;

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  promise.catch(() => {});
  return { promise, resolve, reject };
}

function entryFor(sessionId, phase) {
  const validPhase = ['offset', 'update'].includes(phase) || /^triple:(?:[0-9]|1[0-9])$/.test(phase);
  if (typeof sessionId !== 'string' || !/^[0-9a-f-]{36}$/i.test(sessionId) || !validPhase) {
    throw new TypeError('Invalid read exchange identifier');
  }
  const key = `${sessionId}:${phase}`;
  let entry = rounds.get(key);
  if (!entry) {
    if (rounds.size >= 128) throw new Error('Too many pending read exchanges');
    entry = { ready: deferred(), peer: deferred(), registered: false, received: false };
    entry.timer = setTimeout(() => {
      rounds.delete(key);
      entry.ready.reject(new Error('Read exchange timed out'));
      entry.peer.reject(new Error('Read exchange timed out'));
    }, timeoutMs);
    entry.timer.unref?.();
    rounds.set(key, entry);
  }
  return { key, entry };
}

export function waitForReadExchange(sessionId, phase, local) {
  const { key, entry } = entryFor(sessionId, phase);
  if (entry.registered) throw new Error('Duplicate local read exchange');
  entry.registered = true;
  entry.local = local;
  entry.ready.resolve();
  return entry.peer.promise.finally(() => { clearTimeout(entry.timer); rounds.delete(key); });
}

export async function exchangeRead(sessionId, phase, local) {
  const { key, entry } = entryFor(sessionId, phase);
  await entry.ready.promise;
  if (entry.received) throw new Error('Duplicate peer read exchange');
  entry.received = true;
  entry.peer.resolve(local);
  clearTimeout(entry.timer);
  rounds.delete(key);
  return entry.local;
}
