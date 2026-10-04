import { prepareAndShares, finishAndShare } from './secure-and.js';
import {
  createExtensionReceiver,
  createExtensionSenderReply,
  finishExtensionReceiver,
} from './ot-extension.js';

function validateSenderContext(context) {
  if (!Array.isArray(context?.choices) || !Array.isArray(context?.selectedSeeds) || context.choices.length !== 128 || context.selectedSeeds.length !== 128) {
    throw new TypeError('A completed 128-OT extension sender setup is required');
  }
}

function validateReceiverSeeds(seedPairs) {
  if (!Array.isArray(seedPairs) || seedPairs.length !== 128) throw new TypeError('A completed 128-OT extension receiver setup is required');
}

function makeRound(xShare, yShare, receiverSeedPairs, senderContext) {
  validateSenderContext(senderContext);
  validateReceiverSeeds(receiverSeedPairs);
  const prepared = prepareAndShares(Array.from(xShare), Array.from(yShare));
  const receiver = createExtensionReceiver(receiverSeedPairs, prepared.receiverChoices);
  return {
    state: {
      prepared,
      receiverState: receiver.state,
      receiverRequest: receiver.message,
      senderContext,
    },
    request: {
      // Sender alternatives stay local. Their XOR reveals xShare; the peer
      // receives only ciphertexts made by createExtensionSenderReply.
      receiver: receiver.message,
    },
  };
}

export function startAndRound(xShare, yShare, receiverSeedPairs, senderContext) {
  return makeRound(xShare, yShare, receiverSeedPairs, senderContext);
}

// The responder returns its own receiver request and an OT reply for the
// initiator's request. It never learns the initiator's OT choices.
export function answerAndRound(state, incomingRequest) {
  if (!state?.prepared || !incomingRequest?.receiver) throw new TypeError('Invalid AND round state or incoming request');
  const responseReply = createExtensionSenderReply(
    state.senderContext.selectedSeeds,
    state.senderContext.choices,
    incomingRequest.receiver,
    state.prepared.senderMessages0,
    state.prepared.senderMessages1,
  );
  return {
    receiverRequest: state.receiverRequest,
    senderReply: responseReply,
  };
}

// The initiator completes the responder's OT and creates the final OT reply.
export function finishInitiatedAndRound(state, responderResponse) {
  if (!state?.prepared || !responderResponse?.receiverRequest || !responderResponse?.senderReply) {
    throw new TypeError('Invalid AND round state or responder response');
  }
  const finalReply = createExtensionSenderReply(
    state.senderContext.selectedSeeds,
    state.senderContext.choices,
    responderResponse.receiverRequest,
    state.prepared.senderMessages0,
    state.prepared.senderMessages1,
  );
  const crossTerm = finishExtensionReceiver(state.receiverState, responderResponse.senderReply);
  return { share: finishAndShare(state.prepared, crossTerm), finalReply };
}

export function finishRespondedAndRound(state, finalReply) {
  if (!state?.prepared || !finalReply) throw new TypeError('Invalid AND round state or final reply');
  const crossTerm = finishExtensionReceiver(state.receiverState, finalReply);
  return finishAndShare(state.prepared, crossTerm);
}

