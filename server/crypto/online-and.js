import { registerResponderRound, runInitiatedRound } from './and-round-store.js';
import { startAndRound } from './secure-and-session.js';

export function createOnlineAndCallback({ party, sessionId, senderContext, receiverSeedPairs, peerRequest }) {
  if (party !== 0 && party !== 1) throw new TypeError('party must be 0 or 1');
  if (typeof peerRequest !== 'function') throw new TypeError('peerRequest transport is required');
  let roundId = 0;

  return async (xShare, yShare) => {
    const id = roundId++;
    const localRound = startAndRound(xShare, yShare, receiverSeedPairs, senderContext);
    if (party === 1) return registerResponderRound(sessionId, id, localRound.state);

    return runInitiatedRound(
      sessionId,
      id,
      localRound.state,
      localRound.request,
      (sid, rid, request) => peerRequest('/internal/mpc/and', { sessionId: sid, roundId: rid, request }),
      (sid, rid, finalReply) => peerRequest('/internal/mpc/and/finish', { sessionId: sid, roundId: rid, finalReply }),
    );
  };
}
