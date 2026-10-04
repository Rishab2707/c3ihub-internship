import { Worker } from 'node:worker_threads';

let worker;
let nextId = 0;
const requests = new Map();

function rejectRequests(error) {
  for (const request of requests.values()) request.reject(error);
  requests.clear();
}

export function setupInThread(action, payload) {
  if (!worker) {
    const instance = new Worker(new URL('./ot-setup-worker.js', import.meta.url));
    worker = instance;
    instance.on('message', ({ id, result, error }) => {
      const request = requests.get(id);
      if (!request) return;
      requests.delete(id);
      if (error) request.reject(new Error(error));
      else request.resolve(result);
    });
    instance.on('error', error => { if (worker === instance) rejectRequests(error); });
    instance.on('exit', () => {
      if (worker === instance) { worker = null; rejectRequests(new Error('OT setup worker stopped')); }
    });
  }
  if (requests.size >= 128) return Promise.reject(new Error('Too many OT setup requests'));
  const id = nextId++;
  return new Promise((resolve, reject) => {
    requests.set(id, { resolve, reject });
    worker.postMessage({ id, action, payload });
  });
}

export async function stopSetupThread() {
  if (!worker) return;
  const instance = worker;
  worker = null;
  rejectRequests(new Error('OT setup worker discarded'));
  await instance.terminate();
}

export async function runInitiatorSetupInThread(sessionId, peerRequest) {
  try {
    const offer = await setupInThread('initiator/start', { sessionId });
    const start = await peerRequest('/internal/mpc/setup/start', { sessionId, offer });
    const response = await setupInThread('initiator/respond', { sessionId, ...start });
    const peerResponse = await peerRequest('/internal/mpc/setup/respond', { sessionId, publicB: response.publicB });
    const contexts = await setupInThread('initiator/finish', { ciphertexts: peerResponse.ciphertexts });
    await peerRequest('/internal/mpc/setup/finish', { sessionId, ciphertexts: response.ciphertexts });
    return contexts;
  } finally {
    await stopSetupThread();
  }
}
