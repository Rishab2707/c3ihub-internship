import { parentPort } from 'node:worker_threads';
import { beginOtSetup, answerOtSetupOffer, answerOtSetupPublicB, finishOtSetup,
  beginOtSetupAsResponder, answerOtSetupAsResponder, finishOtSetupAsResponder } from './ot-setup.js';

// Private agreement objects remain inside this thread until setup completes.
// Only public setup messages and the final local OT contexts are cloned out.
let initiator;
parentPort.on('message', ({ id, action, payload }) => {
  try {
    let result;
    if (action === 'initiator/start') {
      if (initiator) throw new Error('OT setup already started');
      initiator = beginOtSetup(payload.sessionId);
      result = initiator.offer;
    } else if (action === 'initiator/respond') {
      const afterOffer = answerOtSetupOffer(initiator.state, payload.offer, payload.sessionId);
      initiator = answerOtSetupPublicB(afterOffer.state, payload.publicB);
      result = { publicB: afterOffer.publicB, ciphertexts: initiator.ciphertexts };
    } else if (action === 'initiator/finish') {
      result = finishOtSetup(initiator.state, payload.ciphertexts);
      initiator = null;
    } else if (action === 'responder/start') {
      result = beginOtSetupAsResponder(payload.sessionId, payload.offer);
    } else if (action === 'responder/respond') {
      result = answerOtSetupAsResponder(payload.sessionId, payload.publicB);
    } else if (action === 'responder/finish') {
      result = finishOtSetupAsResponder(payload.sessionId, payload.ciphertexts);
    } else throw new TypeError('Unknown OT setup action');
    parentPort.postMessage({ id, result });
  } catch (error) {
    parentPort.postMessage({ id, error: error.message });
  }
});
