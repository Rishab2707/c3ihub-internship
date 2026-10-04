import {
  createExtensionReceiverBaseOffer,
  createExtensionSenderBaseReply,
  finishExtensionReceiverBaseOffer,
  finishExtensionSenderBaseReply,
} from './ot-extension.js';

const responderSetups = new Map();

function validateSetupSessionId(sessionId) {
  if (typeof sessionId !== 'string' || sessionId.length < 1 || Buffer.byteLength(sessionId, 'utf8') > 128) {
    throw new TypeError('Invalid OT setup session id');
  }
}

// All messages in this state machine are online. Both processes run the same
// four exchanges so each gets material for sending and receiving extended OTs.
export function beginOtSetup(sessionId) {
  validateSetupSessionId(sessionId);
  const receiverOffer = createExtensionReceiverBaseOffer(sessionId);
  return {
    state: { receiverOfferState: receiverOffer.state, sessionId },
    offer: receiverOffer.message,
  };
}

export function answerOtSetupOffer(state, peerOffer, sessionId = state?.sessionId) {
  if (!state?.receiverOfferState || !Array.isArray(peerOffer?.publicA)) throw new TypeError('Invalid OT setup offer');
  validateSetupSessionId(sessionId);
  if (state.sessionId !== sessionId) throw new Error('OT setup transcript context mismatch');
  const sender = createExtensionSenderBaseReply(peerOffer.publicA, sessionId);
  return {
    state: { ...state, senderState: sender.state },
    publicB: sender.message.publicB,
  };
}

export function answerOtSetupPublicB(state, peerPublicB) {
  if (!state?.senderState || !Array.isArray(peerPublicB)) throw new TypeError('Invalid OT setup public-key response');
  const receiver = finishExtensionReceiverBaseOffer(state.receiverOfferState, peerPublicB);
  return {
    state: { ...state, receiverSeedPairs: receiver.state.seedPairs },
    ciphertexts: receiver.message.ciphertexts,
  };
}

export function finishOtSetup(state, peerCiphertexts) {
  if (!state?.senderState || !Array.isArray(state.receiverSeedPairs) || !Array.isArray(peerCiphertexts)) {
    throw new TypeError('Invalid OT setup completion');
  }
  const senderContext = finishExtensionSenderBaseReply(state.senderState, peerCiphertexts);
  return {
    senderContext,
    receiverSeedPairs: state.receiverSeedPairs,
  };
}

export async function runOtSetupAsInitiator(sessionId, peerRequest) {
  validateSetupSessionId(sessionId);
  if (typeof peerRequest !== 'function') throw new TypeError('Peer transport callback is required');
  const initial = beginOtSetup(sessionId);
  const peerStart = await peerRequest('/internal/mpc/setup/start', { sessionId, offer: initial.offer });
  const afterOffer = answerOtSetupOffer(initial.state, peerStart.offer, sessionId);
  const afterPublicB = answerOtSetupPublicB(afterOffer.state, peerStart.publicB);
  const peerResponse = await peerRequest('/internal/mpc/setup/respond', {
    sessionId,
    publicB: afterOffer.publicB,
  });
  const contexts = finishOtSetup(afterPublicB.state, peerResponse.ciphertexts);
  await peerRequest('/internal/mpc/setup/finish', { sessionId, ciphertexts: afterPublicB.ciphertexts });
  return contexts;
}

export function beginOtSetupAsResponder(sessionId, peerOffer) {
  validateSetupSessionId(sessionId);
  const now = Date.now();
  for (const [key, entry] of responderSetups) if (now - entry.createdAt > 5 * 60_000) responderSetups.delete(key);
  if (responderSetups.size >= 128) throw new Error('Too many pending OT setup sessions');
  if (responderSetups.has(sessionId)) throw new Error('Duplicate OT setup session');
  const initial = beginOtSetup(sessionId);
  const answer = answerOtSetupOffer(initial.state, peerOffer, sessionId);
  responderSetups.set(sessionId, { state: answer.state, offer: initial.offer, createdAt: now });
  return { offer: initial.offer, publicB: answer.publicB };
}

export function answerOtSetupAsResponder(sessionId, publicB) {
  const entry = responderSetups.get(sessionId);
  if (!entry) throw new Error('OT setup session not found');
  const response = answerOtSetupPublicB(entry.state, publicB);
  entry.state = response.state;
  return { ciphertexts: response.ciphertexts };
}

export function finishOtSetupAsResponder(sessionId, peerCiphertexts) {
  const entry = responderSetups.get(sessionId);
  if (!entry) throw new Error('OT setup session not found');
  const contexts = finishOtSetup(entry.state, peerCiphertexts);
  responderSetups.delete(sessionId);
  return contexts;
}
