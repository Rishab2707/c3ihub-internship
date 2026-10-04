import { answerAndRound, finishInitiatedAndRound, finishRespondedAndRound } from './secure-and-session.js';

const rounds = new Map();
const MAX_PENDING_ROUNDS = 128;
const ROUND_TIMEOUT_MS = 120_000;

function keyFor(sessionId, roundId) {
  if (typeof sessionId !== 'string' || !/^[0-9a-f-]{16,64}$/i.test(sessionId)) throw new TypeError('Invalid session id');
  if (!Number.isSafeInteger(roundId) || roundId < 0) throw new TypeError('Invalid round id');
  return `${sessionId}:${roundId}`;
}

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  // Timeout can reject a not-yet-awaited rendezvous promise when a peer
  // disconnects. Keep that from becoming a process-level unhandled rejection.
  promise.catch(() => {});
  return { promise, resolve, reject };
}

function getOrCreate(key) {
  let entry = rounds.get(key);
  if (entry) return entry;
  if (rounds.size >= MAX_PENDING_ROUNDS) throw new Error('Too many pending MPC rounds');
  entry = { ready: deferred(), complete: deferred(), state: null, timer: null };
  entry.timer = setTimeout(() => {
    rounds.delete(key);
    const error = new Error('MPC round timed out');
    entry.ready.reject(error);
    entry.complete.reject(error);
  }, ROUND_TIMEOUT_MS);
  rounds.set(key, entry);
  return entry;
}

export function registerResponderRound(sessionId, roundId, state) {
  const key = keyFor(sessionId, roundId);
  const entry = getOrCreate(key);
  if (entry.state) throw new Error('Duplicate MPC round registration');
  entry.state = state;
  entry.ready.resolve();
  return entry.complete.promise.finally(() => {
    clearTimeout(entry.timer);
    rounds.delete(key);
  });
}

export async function answerInitiatorRound(sessionId, roundId, request) {
  const key = keyFor(sessionId, roundId);
  const entry = getOrCreate(key);
  await entry.ready.promise;
  if (entry.answered) throw new Error('Duplicate MPC round request');
  entry.answered = true;
  return answerAndRound(entry.state, request);
}

export function completeResponderRound(sessionId, roundId, finalReply) {
  const key = keyFor(sessionId, roundId);
  const entry = rounds.get(key);
  if (!entry || !entry.state || !entry.answered) throw new Error('MPC round is not awaiting completion');
  const share = finishRespondedAndRound(entry.state, finalReply);
  entry.complete.resolve(share);
}

export async function runInitiatedRound(sessionId, roundId, state, request, peerStart, peerFinish) {
  keyFor(sessionId, roundId);
  if (typeof peerStart !== 'function' || typeof peerFinish !== 'function') throw new TypeError('Peer transport callbacks are required');
  const response = await peerStart(sessionId, roundId, request);
  const { share, finalReply } = finishInitiatedAndRound(state, response);
  await peerFinish(sessionId, roundId, finalReply);
  return share;
}
