import { randomBytes } from 'node:crypto';
import { prepareCspirReceiver, prepareCspirSender, finishCspirReceiver } from './cspir.js';
import { generateDuoramDpfShare } from './duoram-dpf.js';
import { createOnlineAndCallback } from './online-and.js';
import { waitForDpfControl } from './dpf-control-store.js';
import { generateOtTriplePool, createTripleAndCallback } from './multiplication-triples.js';
import { waitForReadExchange } from './read-round-store.js';

export function beginPreprocessing(id, party, domainBits, contexts) {
  // Independent of all browser inputs and database contents.
  const randomIndexBits = Array.from(randomBytes(domainBits), byte => byte & 1);
  const receiver = prepareCspirReceiver(randomIndexBits, contexts.receiverSeedPairs);
  return { id, party, domainBits, randomIndexBits, receiver, consumed: false };
}

export function answerPreprocessingQuery(item, peerRequest, contexts) {
  const sender = prepareCspirSender({ request: peerRequest, domainBits: item.domainBits,
    senderContext: contexts.senderContext, context: `${item.id}:${item.party ^ 1}` });
  item.pads = sender.pads;
  return sender.reply;
}

export function finishPreprocessingQuery(item, reply) {
  if (item.selectedPad !== undefined) throw new Error('Preprocessing query was already completed');
  item.selectedPad = finishCspirReceiver({ state: item.receiver.state, reply,
    indexBits: item.randomIndexBits, context: `${item.id}:${item.party}` });
  delete item.receiver;
}

export async function generatePreprocessedDpf(item, contexts, peerRequest) {
  const otMultiply = createOnlineAndCallback({ party: item.party, sessionId: item.id,
    senderContext: contexts.senderContext, receiverSeedPairs: contexts.receiverSeedPairs, peerRequest });
  // Prepare every random triple before DPF generation uses any operands.
  const pool = await generateOtTriplePool(item.domainBits * 128, otMultiply);
  const exchangeOpenings = item.party === 0
    ? (roundId, shares) => peerRequest('/internal/mpc/triples/open', { sessionId: item.id, roundId, ...shares })
    : (roundId, shares) => waitForReadExchange(item.id, `triple:${roundId}`, shares);
  const andShares = createTripleAndCallback({ party: item.party, pool, exchangeOpenings });
  const exchangeControlShares = item.party === 0
    ? (level, left, right, wordShare) => peerRequest('/internal/mpc/dpf/control', { sessionId: item.id, level, left, right, wordShare })
    : (level, left, right, wordShare) => waitForDpfControl(item.id, level, left, right, wordShare);
  try {
    await generateDuoramDpfShare({ party: item.party, domainBits: item.domainBits,
      indexShareBits: item.randomIndexBits, andShares, exchangeControlShares,
      onEvaluation: evaluation => { item.evaluation = evaluation; } });
    if (pool.remaining !== 0) throw new Error('DPF did not consume its complete triple batch');
  } finally {
    pool.discard();
  }
}

export function consumePreprocessing(item) {
  if (!item || item.consumed || item.selectedPad === undefined || !item.pads || !item.evaluation) {
    throw new Error('Fresh completed preprocessing is required');
  }
  // Burn before either party opens an offset; failures may never retry it.
  item.consumed = true;
  return item;
}
