import http from 'node:http';
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import https from 'node:https';
import { readFileSync } from 'node:fs';
import { answerInitiatorRound, completeResponderRound } from './crypto/and-round-store.js';
import { exchangeDpfControl } from './crypto/dpf-control-store.js';
import { setupInThread, stopSetupThread, runInitiatorSetupInThread } from './crypto/ot-setup-thread.js';
import { runSharedBitOperation } from './crypto/operation.js';
import { beginPreprocessing, answerPreprocessingQuery, finishPreprocessingQuery, generatePreprocessedDpf, consumePreprocessing } from './crypto/preprocessing.js';
import { exchangeRead } from './crypto/read-round-store.js';

const role = process.argv[2];
if (!['a', 'b'].includes(role)) throw new Error('Start as: node server/server.js a|b');
const portA = Number(process.env.DUORAM_PORT_A || 4101);
const portB = Number(process.env.DUORAM_PORT_B || 4102);
if (!Number.isInteger(portA) || !Number.isInteger(portB) || portA < 1 || portA > 65_535 || portB < 1 || portB > 65_535 || portA === portB) {
  throw new Error('DUORAM_PORT_A and DUORAM_PORT_B must be distinct TCP ports');
}
const ownPort = role === 'a' ? portA : portB;
const peerPort = role === 'a' ? portB : portA;
const listenHost = process.env.DUORAM_HOST || '127.0.0.1';
const defaultPeerScheme = process.env.DUORAM_TLS_KEY_PATH ? 'https' : 'http';
const peerUrl = new URL(process.env.DUORAM_PEER_URL || `${defaultPeerScheme}://127.0.0.1:${peerPort}`);
const SIZE = Number(process.env.DB_SIZE || 2 ** 16);
if (!Number.isSafeInteger(SIZE) || SIZE < 1 || SIZE > 1_000_000) throw new Error('DB_SIZE must be an integer from 1 to 1,000,000');
const DOMAIN_BITS = Math.max(1, Math.ceil(Math.log2(SIZE)));
const PROTOCOL_WIRE_VERSION = 'duoram-preprocessed-cspir-triples-aes-bit-v11';
const INSTANCE_ID = randomUUID();
let peerInstanceId = null;
const PEER_TOKEN = process.env.DUORAM_PEER_TOKEN || '';
const PEER_TOKEN_VALID = /^[0-9a-f]{64}$/i.test(PEER_TOKEN);
const allowedOriginConfig = process.env.DUORAM_ALLOWED_ORIGINS;
const ALLOWED_ORIGINS = new Set(allowedOriginConfig === undefined
  ? ['http://localhost:5173', 'http://127.0.0.1:5173']
  : allowedOriginConfig.split(',').map(origin => origin.trim()).filter(Boolean));
const tlsPaths = [process.env.DUORAM_TLS_KEY_PATH, process.env.DUORAM_TLS_CERT_PATH, process.env.DUORAM_TLS_CA_PATH];
const hasAnyTlsPath = tlsPaths.some(Boolean);
if (hasAnyTlsPath && tlsPaths.some(value => !value)) {
  throw new Error('DUORAM_TLS_KEY_PATH, DUORAM_TLS_CERT_PATH, and DUORAM_TLS_CA_PATH must be configured together');
}
const tlsOptions = hasAnyTlsPath ? {
  key: readFileSync(tlsPaths[0]),
  cert: readFileSync(tlsPaths[1]),
  ca: readFileSync(tlsPaths[2]),
} : null;
if (!['http:', 'https:'].includes(peerUrl.protocol)) throw new Error('DUORAM_PEER_URL must use HTTP or HTTPS');
if (tlsOptions && peerUrl.protocol !== 'https:') throw new Error('DUORAM_PEER_URL must use HTTPS when TLS certificates are configured');
const securePeerTransport = Boolean(tlsOptions && peerUrl.protocol === 'https:');
const loopbackHosts = ['127.0.0.1', '::1', 'localhost'];
if (!loopbackHosts.includes(listenHost) && !tlsOptions) {
  throw new Error('TLS certificates are required when DUORAM_HOST is not loopback');
}
const PROTOCOL_VALIDATED = false;
const testOnlyLocalOverride = process.env.NODE_ENV === 'test' &&
  process.env.DUORAM_TEST_ENABLE_ORAM === '1' &&
  loopbackHosts.includes(listenHost) && loopbackHosts.includes(peerUrl.hostname) &&
  (peerUrl.protocol === 'http:' || securePeerTransport);
const ENABLED = (PROTOCOL_VALIDATED || testOnlyLocalOverride) &&
  process.env.ENABLE_ONLINE_ORAM === '1' && PEER_TOKEN_VALID &&
  (securePeerTransport || testOnlyLocalOverride);
let protocolFault = false;

function operationsEnabled() {
  return ENABLED && !protocolFault;
}

function closeRuntimeGate(error) {
  protocolFault = true;
  console.error(`Server ${role.toUpperCase()} stopped secure operations; restart both servers together: ${error.message}`);
}

// A hardcoded zero database. Each party initially owns a zero XOR share.
const databaseShare = new Uint8Array(SIZE);
const clientInputs = new Map();
const backgroundOperations = new Map();
const operationResults = new Map();
const resultAuthorizations = new Map();
const stagedDatabaseShares = new Map();
const committedDatabaseUpdates = new Map();
const seenSessions = new Map();
const MAX_BACKGROUND_OPERATIONS = 128;
const MAX_SEEN_SESSIONS = 4096;
const SESSION_TOMBSTONE_TTL_MS = 10 * 60_000;
const COMPLETED_OPERATION_TTL_MS = 5 * 60_000;
let operationTail = Promise.resolve();
let queuedOperations = 0;
let initiatorOtContexts = null;
let initiatorOtSetupPromise = null;
let responderOtContexts = null;
let preparedItem = null;
let preparationPromise = null;
let preprocessingError = null;
const responderPreprocessing = new Map();
const seenPreprocessing = new Map();

function json(res, status, value) {
  res.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
    'x-duoram-instance': INSTANCE_ID,
  });
  res.end(JSON.stringify(value));
}

function applyBrowserCors(req, res) {
  const origin = req.headers.origin;
  if (!origin) return true;
  if (!ALLOWED_ORIGINS.has(origin)) return false;
  res.setHeader('access-control-allow-origin', origin);
  res.setHeader('access-control-allow-headers', 'content-type, x-duoram-result-token');
  res.setHeader('access-control-allow-methods', 'GET,POST,OPTIONS');
  res.setHeader('vary', 'Origin');
  return true;
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => {
      raw += chunk;
      if (raw.length > 64_000_000) {
        reject(new Error('Request body too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try { resolve(JSON.parse(raw || '{}')); }
      catch (error) { reject(error); }
    });
    req.on('error', reject);
  });
}

function isPeerRequest(req) {
  if (!PEER_TOKEN_VALID) return false;
  const supplied = Buffer.from(req.headers['x-duoram-peer-token'] || '');
  const expected = Buffer.from(PEER_TOKEN);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

function validSessionId(value) {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function requirePeerInstance(instanceId) {
  if (!validSessionId(instanceId) || (peerInstanceId !== null && peerInstanceId !== instanceId)) {
    const error = new Error('Peer process changed or its lifetime identifier is missing; restart both servers together');
    closeRuntimeGate(error);
    throw error;
  }
  peerInstanceId = instanceId;
}

function validBits(bits, length) {
  return Array.isArray(bits) && bits.length === length && bits.every(bit => bit === 0 || bit === 1);
}

async function sendPeer(path, payload) {
  if (!PEER_TOKEN) throw new Error('DUORAM_PEER_TOKEN must be configured for MPC traffic');
  if (!path.startsWith('/internal/')) throw new Error('Peer requests must target internal routes');
  const target = new URL(path, peerUrl);
  const body = Buffer.from(JSON.stringify(payload));
  const transport = target.protocol === 'https:' ? https : http;
  const response = await new Promise((resolve, reject) => {
    const request = transport.request(target, {
      agent: false,
      method: 'POST',
      ca: target.protocol === 'https:' ? tlsOptions?.ca : undefined,
      headers: {
        'content-type': 'application/json',
        'content-length': body.length,
        'x-duoram-peer-token': PEER_TOKEN,
        'x-duoram-peer-instance': INSTANCE_ID,
      },
    }, incoming => {
      const chunks = [];
      let size = 0;
      incoming.on('data', chunk => {
        size += chunk.length;
        if (size > 64_000_000) {
          request.destroy(new Error('Peer response is too large'));
          return;
        }
        chunks.push(chunk);
      });
      incoming.on('end', () => {
        try {
          resolve({ status: incoming.statusCode, instanceId: incoming.headers['x-duoram-instance'], data: JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}') });
        } catch (error) { reject(error); }
      });
    });
    request.setTimeout(path.startsWith('/internal/mpc/setup/') ? 300_000 : 120_000,
      () => request.destroy(new Error('Peer request timed out')));
    request.on('error', error => reject(new Error(`Peer request ${target.pathname} failed: ${error.message}`)));
    request.end(body);
  });
  requirePeerInstance(response.instanceId);
  if (response.status < 200 || response.status >= 300) {
    const error = new Error(response.data.error || `Peer returned HTTP ${response.status}`);
    error.status = response.status;
    if (response.data.restartRequired === true) closeRuntimeGate(error);
    throw error;
  }
  return response.data;
}

function rememberResult(sessionId, result) {
  if (operationResults.size >= 128) {
    const oldest = operationResults.keys().next().value;
    operationResults.delete(oldest);
    resultAuthorizations.delete(oldest);
  }
  operationResults.set(sessionId, result);
  const authorization = resultAuthorizations.get(sessionId);
  if (authorization) authorization.expiresAt = Date.now() + COMPLETED_OPERATION_TTL_MS;
  seenSessions.set(sessionId, Date.now() + SESSION_TOMBSTONE_TTL_MS);
  const timer = setTimeout(() => {
    if (operationResults.get(sessionId) === result) {
      operationResults.delete(sessionId);
      resultAuthorizations.delete(sessionId);
    }
  }, 5 * 60_000);
  timer.unref?.();
}

async function runPartyOperation(sessionId, operation, indexShareBits, valueShare, preprocessing) {
  return runSharedBitOperation({
    party: role === 'a' ? 0 : 1,
    sessionId,
    operation,
    indexShareBits,
    valueShare,
    databaseShare,
    preprocessing,
    peerRequest: sendPeer,
  });
}

async function getInitiatorOtContexts() {
  if (initiatorOtContexts) return initiatorOtContexts;
  if (!initiatorOtSetupPromise) {
    const setupSessionId = randomUUID();
    initiatorOtSetupPromise = runInitiatorSetupInThread(setupSessionId, sendPeer)
      .then(contexts => {
        initiatorOtContexts = contexts;
        return contexts;
      })
      .catch(error => {
        initiatorOtSetupPromise = null;
        throw error;
      });
  }
  return initiatorOtSetupPromise;
}

async function runCoordinatorOperation(sessionId, operation, indexShareBits, valueShare) {
  // Check the paired database lifetime before starting or reusing OT state.
  const peer = await sendPeer('/internal/peer/check', {
    protocolVersion: PROTOCOL_WIRE_VERSION, databaseSize: SIZE, domainBits: DOMAIN_BITS,
  });
  if (peer.role !== 'b') throw new Error('Coordinator must be paired with server B');
  const preprocessing = await takePreprocessing();
  try {
    await sendPeer('/internal/op/run', {
      sessionId,
      operation,
      protocolVersion: PROTOCOL_WIRE_VERSION,
      databaseSize: SIZE,
      domainBits: DOMAIN_BITS,
      preprocessingId: preprocessing.id,
    });
  } catch (error) {
    // A burned its item before this request. If B rejected the operation
    // before reserving it, discard B's orphaned pool item as well.
    await sendPeer('/internal/preprocess/abort', { preprocessingId: preprocessing.id }).catch(() => {});
    // A 409 means party B lost its matching client input or OT setup. Do not
    // reuse the now-stale initiator extension state on the next client request.
    if (error.status === 409) {
      initiatorOtContexts = null;
      initiatorOtSetupPromise = null;
    }
    throw error;
  }
  const result = await runPartyOperation(sessionId, operation, indexShareBits, valueShare, preprocessing);
  await sendPeer('/internal/op/wait', { sessionId });
  if (operation === 'insert') {
    // The peer endpoint is idempotent, so retry an ambiguous transport failure
    // before applying A's staged share.
    let commitError;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await sendPeer('/internal/op/commit', { sessionId });
        commitError = null;
        break;
      } catch (error) {
        commitError = error;
        if (error.status && error.status < 500) break;
        if (attempt < 2) await new Promise(resolve => setTimeout(resolve, 200 * (2 ** attempt)));
      }
    }
    if (commitError) {
      // B may already have committed despite a lost response. Continuing
      // would evaluate subsequent accesses against inconsistent XOR shares.
      closeRuntimeGate(commitError);
      throw commitError;
    }
    databaseShare.set(result.updatedDatabaseShare);
    delete result.updatedDatabaseShare;
  }
  if (operationsEnabled()) void ensurePreprocessing().catch(() => {});
  return result;
}

async function ensurePreprocessing() {
  if (preparedItem) return preparedItem;
  if (!preparationPromise) {
    let startedId;
    preparationPromise = (async () => {
      const peer = await sendPeer('/internal/peer/check', {
        protocolVersion: PROTOCOL_WIRE_VERSION, databaseSize: SIZE, domainBits: DOMAIN_BITS,
      });
      if (peer.role !== 'b') throw new Error('Preprocessing requires server B');
      const contexts = await getInitiatorOtContexts();
      const item = beginPreprocessing(randomUUID(), 0, DOMAIN_BITS, contexts);
      startedId = item.id;
      const response = await sendPeer('/internal/preprocess/start', {
        preprocessingId: item.id, request: item.receiver.message,
      });
      const reply = answerPreprocessingQuery(item, response.request, contexts);
      finishPreprocessingQuery(item, response.reply);
      await sendPeer('/internal/preprocess/finish-query', { preprocessingId: item.id, reply });
      await generatePreprocessedDpf(item, contexts, sendPeer);
      await sendPeer('/internal/preprocess/wait', { preprocessingId: item.id });
      preparedItem = item;
      preprocessingError = null;
      return item;
    })().catch(async error => {
      if (startedId && operationsEnabled()) {
        await sendPeer('/internal/preprocess/abort', { preprocessingId: startedId }).catch(() => {});
      }
      preprocessingError = 'Preprocessing failed; retry the operation or restart both servers';
      throw error;
    }).finally(() => { preparationPromise = null; });
  }
  return preparationPromise;
}

async function takePreprocessing() {
  const item = await ensurePreprocessing();
  preparedItem = null;
  return consumePreprocessing(item);
}

async function enqueueClientOperation(res, operation) {
  if (queuedOperations >= MAX_BACKGROUND_OPERATIONS) {
    return json(res, 503, { error: 'Too many queued operations' });
  }
  queuedOperations++;
  const run = operationTail.then(operation);
  operationTail = run.catch(() => {});
  try {
    await run;
  } finally {
    queuedOperations--;
  }
}

const requestHandler = async (req, res) => {
  if (!applyBrowserCors(req, res)) return json(res, 403, { error: 'Browser origin is not allowed' });
  if (req.method === 'OPTIONS') return json(res, 204, {});
  try {
    if (req.method === 'GET' && req.url === '/api/status') {
      return json(res, 200, {
        role,
        size: SIZE,
        domainBits: DOMAIN_BITS,
        ready: true,
        secureOram: false,
        operationsEnabled: operationsEnabled(),
        restartRequired: protocolFault,
        securePeerTransport,
        protocol: 'two-party DUORAM read with encrypted-download CSPIR and shifted offline DPF; research prototype',
        preprocessing: {
          ready: role === 'a' ? Number(Boolean(preparedItem)) : [...responderPreprocessing.values()].filter(entry => entry.complete).length,
          pending: role === 'a' ? Boolean(preparationPromise) : [...responderPreprocessing.values()].some(entry => !entry.complete),
          error: role === 'a' ? preprocessingError : null,
        },
      });
    }

    if (req.method === 'POST' && req.url === '/api/share') {
      if (role !== 'b' || !operationsEnabled()) return json(res, 501, { error: 'Secure operations are disabled' });
      const { sessionId, indexShareBits, valueShare = 0, resultToken } = await parseBody(req);
      if (!validSessionId(sessionId) || !validBits(indexShareBits, DOMAIN_BITS) || (valueShare !== 0 && valueShare !== 1) ||
          typeof resultToken !== 'string' || !/^[0-9a-f]{64}$/i.test(resultToken)) {
        return json(res, 400, { error: 'Invalid client shares' });
      }
      const now = Date.now();
      for (const [key, input] of clientInputs) if (now - input.createdAt > 5 * 60_000) {
        clientInputs.delete(key);
        resultAuthorizations.delete(key);
      }
      for (const [key, authorization] of resultAuthorizations) if (now >= authorization.expiresAt) resultAuthorizations.delete(key);
      for (const [key, expiresAt] of seenSessions) if (now >= expiresAt) seenSessions.delete(key);
      for (const [key, expiresAt] of committedDatabaseUpdates) if (now >= expiresAt) committedDatabaseUpdates.delete(key);
      if (clientInputs.size >= 128 || clientInputs.has(sessionId) || backgroundOperations.has(sessionId) ||
          operationResults.has(sessionId) || seenSessions.has(sessionId)) {
        return json(res, 409, { error: 'Session already exists or capacity reached' });
      }
      if (seenSessions.size >= MAX_SEEN_SESSIONS || resultAuthorizations.size >= MAX_SEEN_SESSIONS) return json(res, 503, { error: 'Too many recent sessions' });
      seenSessions.set(sessionId, now + SESSION_TOMBSTONE_TTL_MS);
      clientInputs.set(sessionId, { indexShareBits, valueShare, createdAt: now });
      // This capability is sent only on the browser-to-B connection. Session
      // IDs are public to A and cannot authorize reading B's private output.
      resultAuthorizations.set(sessionId, {
        digest: createHash('sha256').update(Buffer.from(resultToken, 'hex')).digest(),
        expiresAt: now + COMPLETED_OPERATION_TTL_MS,
      });
      return json(res, 202, { accepted: true });
    }

    if (req.method === 'POST' && req.url === '/api/access') {
      if (role !== 'a' || !operationsEnabled()) return json(res, 501, { error: 'Secure operations are disabled' });
      const { sessionId, indexShareBits } = await parseBody(req);
      if (!validSessionId(sessionId) || !validBits(indexShareBits, DOMAIN_BITS)) return json(res, 400, { error: 'Invalid client shares' });
      return await enqueueClientOperation(res, async () => {
        if (!operationsEnabled()) return json(res, 501, { error: 'Secure operations are disabled' });
        const result = await runCoordinatorOperation(sessionId, 'access', indexShareBits, 0);
        json(res, 200, { sessionId, share: result.share, validityShare: result.validityShare });
      });
    }

    if (req.method === 'POST' && req.url === '/api/insert') {
      if (role !== 'a' || !operationsEnabled()) return json(res, 501, { error: 'Secure operations are disabled' });
      const { sessionId, indexShareBits, valueShare } = await parseBody(req);
      if (!validSessionId(sessionId) || !validBits(indexShareBits, DOMAIN_BITS) || (valueShare !== 0 && valueShare !== 1)) {
        return json(res, 400, { error: 'Invalid client shares' });
      }
      return await enqueueClientOperation(res, async () => {
        if (!operationsEnabled()) return json(res, 501, { error: 'Secure operations are disabled' });
        const result = await runCoordinatorOperation(sessionId, 'insert', indexShareBits, valueShare);
        json(res, 200, { sessionId, ok: true, validityShare: result.validityShare });
      });
    }

    if (req.method === 'GET' && role === 'b' && req.url.startsWith('/api/result/')) {
      if (!operationsEnabled()) return json(res, 501, { error: 'Secure operations are disabled' });
      const sessionId = req.url.slice('/api/result/'.length);
      if (!validSessionId(sessionId)) return json(res, 400, { error: 'Invalid session id' });
      const resultToken = req.headers['x-duoram-result-token'];
      const authorization = resultAuthorizations.get(sessionId);
      if (!authorization || Date.now() >= authorization.expiresAt || typeof resultToken !== 'string' ||
          !/^[0-9a-f]{64}$/i.test(resultToken) || !timingSafeEqual(authorization.digest,
            createHash('sha256').update(Buffer.from(resultToken, 'hex')).digest())) {
        return json(res, 403, { error: 'Result authorization required' });
      }
      if (operationResults.has(sessionId)) {
        const result = operationResults.get(sessionId);
        operationResults.delete(sessionId);
        resultAuthorizations.delete(sessionId);
        return json(res, 200, result);
      }
      if (backgroundOperations.has(sessionId)) return json(res, 202, { pending: true });
      return json(res, 404, { error: 'Result not found' });
    }

    if (req.method === 'POST' && req.url.startsWith('/internal/')) {
      if (!isPeerRequest(req)) return json(res, 404, { error: 'Not found' });
      if (!operationsEnabled()) return json(res, 501, { error: 'Secure operations are disabled', restartRequired: protocolFault });
      requirePeerInstance(req.headers['x-duoram-peer-instance']);
      const body = await parseBody(req);

      if (role === 'b' && req.url === '/internal/peer/check') {
        if (body.protocolVersion !== PROTOCOL_WIRE_VERSION || body.databaseSize !== SIZE || body.domainBits !== DOMAIN_BITS) {
          return json(res, 400, { error: 'Peer protocol configuration mismatch' });
        }
        return json(res, 200, { role, protocolVersion: PROTOCOL_WIRE_VERSION });
      }

      if (role === 'b' && req.url === '/internal/mpc/setup/start') {
        return json(res, 200, await setupInThread('responder/start', body));
      }
      if (role === 'b' && req.url === '/internal/mpc/setup/respond') {
        return json(res, 200, await setupInThread('responder/respond', body));
      }
      if (role === 'b' && req.url === '/internal/mpc/setup/finish') {
        responderOtContexts = await setupInThread('responder/finish', body);
        await stopSetupThread();
        return json(res, 200, { ok: true });
      }
      if (role === 'b' && req.url === '/internal/mpc/and') {
        return json(res, 200, await answerInitiatorRound(body.sessionId, body.roundId, body.request));
      }
      if (role === 'b' && req.url === '/internal/mpc/and/finish') {
        completeResponderRound(body.sessionId, body.roundId, body.finalReply);
        return json(res, 200, { ok: true });
      }
      if (role === 'b' && req.url === '/internal/mpc/triples/open') {
        if (!validSessionId(body.sessionId) || !Number.isInteger(body.roundId) || body.roundId < 0 ||
            body.roundId >= DOMAIN_BITS || !validBits(body.dShare, 128) || !validBits(body.eShare, 128)) {
          return json(res, 400, { error: 'Invalid masked triple opening' });
        }
        return json(res, 200, await exchangeRead(body.sessionId, `triple:${body.roundId}`,
          { dShare: body.dShare, eShare: body.eShare }));
      }
      if (role === 'b' && req.url === '/internal/mpc/dpf/control') {
        return json(res, 200, await exchangeDpfControl(body.sessionId, body.level, body.left, body.right, body.wordShare));
      }
      if (role === 'b' && req.url === '/internal/preprocess/start') {
        const id = body.preprocessingId;
        const now = Date.now();
        for (const [key, expires] of seenPreprocessing) if (expires <= now) seenPreprocessing.delete(key);
        if (!validSessionId(id) || !responderOtContexts || responderPreprocessing.size >= 2 ||
            responderPreprocessing.has(id) || seenPreprocessing.has(id) || seenPreprocessing.size >= MAX_SEEN_SESSIONS) {
          return json(res, 409, { error: 'Preprocessing unavailable or identifier already used' });
        }
        seenPreprocessing.set(id, now + SESSION_TOMBSTONE_TTL_MS);
        const item = beginPreprocessing(id, 1, DOMAIN_BITS, responderOtContexts);
        const request = item.receiver.message;
        const reply = answerPreprocessingQuery(item, body.request, responderOtContexts);
        const entry = { item, complete: false };
        entry.timer = setTimeout(() => { responderPreprocessing.delete(id); }, SESSION_TOMBSTONE_TTL_MS);
        entry.timer.unref?.();
        responderPreprocessing.set(id, entry);
        entry.task = generatePreprocessedDpf(item, responderOtContexts, sendPeer).catch(error => {
          entry.error = error;
        });
        return json(res, 200, { request, reply });
      }
      if (role === 'b' && req.url === '/internal/preprocess/finish-query') {
        const entry = responderPreprocessing.get(body.preprocessingId);
        if (!entry) return json(res, 409, { error: 'Unknown preprocessing item' });
        finishPreprocessingQuery(entry.item, body.reply);
        return json(res, 200, { ok: true });
      }
      if (role === 'b' && req.url === '/internal/preprocess/wait') {
        const entry = responderPreprocessing.get(body.preprocessingId);
        if (!entry) return json(res, 409, { error: 'Unknown preprocessing item' });
        await entry.task;
        if (entry.error || entry.item.selectedPad === undefined) throw new Error('Preprocessing failed');
        entry.complete = true;
        // A completed, bounded pool item may wait indefinitely for a client.
        clearTimeout(entry.timer);
        return json(res, 200, { ready: true });
      }
      if (role === 'b' && req.url === '/internal/preprocess/abort') {
        const entry = responderPreprocessing.get(body.preprocessingId);
        if (entry) clearTimeout(entry.timer);
        responderPreprocessing.delete(body.preprocessingId);
        return json(res, 200, { discarded: true });
      }
      if (role === 'b' && req.url === '/internal/read/exchange') {
        return json(res, 200, await exchangeRead(body.sessionId, body.phase, body.contribution));
      }
      if (role === 'b' && req.url === '/internal/op/run') {
        if (!ENABLED || !validSessionId(body.sessionId) || !['access', 'insert'].includes(body.operation)) return json(res, 400, { error: 'Invalid operation request' });
        if (body.protocolVersion !== PROTOCOL_WIRE_VERSION || body.databaseSize !== SIZE || body.domainBits !== DOMAIN_BITS) {
          clientInputs.delete(body.sessionId);
          return json(res, 400, { error: 'Peer protocol configuration mismatch' });
        }
        if (backgroundOperations.size >= MAX_BACKGROUND_OPERATIONS) return json(res, 503, { error: 'Too many active operations' });
        const input = clientInputs.get(body.sessionId);
        const contexts = responderOtContexts;
        const preprocessingEntry = responderPreprocessing.get(body.preprocessingId);
        if (!input || Date.now() - input.createdAt > 5 * 60_000 || !contexts || backgroundOperations.has(body.sessionId)) {
          clientInputs.delete(body.sessionId);
          return json(res, 409, { error: 'Operation inputs or OT setup are unavailable' });
        }
        if (!preprocessingEntry?.complete) return json(res, 409, { error: 'Fresh completed preprocessing is unavailable' });
        const preprocessing = consumePreprocessing(preprocessingEntry.item);
        responderPreprocessing.delete(body.preprocessingId);
        clearTimeout(preprocessingEntry.timer);
        clientInputs.delete(body.sessionId);
        const task = runPartyOperation(body.sessionId, body.operation, input.indexShareBits, input.valueShare, preprocessing)
          .then(result => {
            if (body.operation === 'insert') {
              if (stagedDatabaseShares.size >= MAX_BACKGROUND_OPERATIONS) throw new Error('Too many staged database updates');
              const staged = {
                share: result.updatedDatabaseShare,
                result: { ok: true, validityShare: result.validityShare },
                cleanupTimer: null,
              };
              staged.cleanupTimer = setTimeout(() => {
                if (stagedDatabaseShares.get(body.sessionId) === staged) stagedDatabaseShares.delete(body.sessionId);
              }, COMPLETED_OPERATION_TTL_MS);
              staged.cleanupTimer.unref?.();
              stagedDatabaseShares.set(body.sessionId, staged);
              delete result.updatedDatabaseShare;
            } else {
              rememberResult(body.sessionId, { share: result.share, validityShare: result.validityShare });
            }
            return { complete: true };
          })
          .catch(error => {
            console.error(`MPC operation ${body.sessionId} failed:`, error.message);
            rememberResult(body.sessionId, { error: 'Secure operation failed' });
            return { error: 'Secure operation failed' };
          });
        const operationEntry = { task, cleanupTimer: null };
        backgroundOperations.set(body.sessionId, operationEntry);
        task.then(() => {
          operationEntry.cleanupTimer = setTimeout(() => {
            if (backgroundOperations.get(body.sessionId) === operationEntry) backgroundOperations.delete(body.sessionId);
          }, COMPLETED_OPERATION_TTL_MS);
          operationEntry.cleanupTimer.unref?.();
        });
        return json(res, 202, { started: true });
      }
      if (role === 'b' && req.url === '/internal/op/wait') {
        const operationEntry = backgroundOperations.get(body.sessionId);
        if (!operationEntry) return json(res, 409, { error: 'Operation is not running' });
        const result = await operationEntry.task;
        backgroundOperations.delete(body.sessionId);
        if (operationEntry.cleanupTimer) clearTimeout(operationEntry.cleanupTimer);
        if (result?.error) throw new Error(result.error);
        return json(res, 200, { complete: true });
      }
      if (role === 'b' && req.url === '/internal/op/commit') {
        if (!validSessionId(body.sessionId)) return json(res, 400, { error: 'Invalid session id' });
        const now = Date.now();
        for (const [key, expiresAt] of committedDatabaseUpdates) if (now >= expiresAt) committedDatabaseUpdates.delete(key);
        if (committedDatabaseUpdates.has(body.sessionId)) return json(res, 200, { committed: true });
        const staged = stagedDatabaseShares.get(body.sessionId);
        if (!staged) return json(res, 409, { error: 'No staged database update' });
        databaseShare.set(staged.share);
        clearTimeout(staged.cleanupTimer);
        stagedDatabaseShares.delete(body.sessionId);
        committedDatabaseUpdates.set(body.sessionId, now + COMPLETED_OPERATION_TTL_MS);
        rememberResult(body.sessionId, staged.result);
        return json(res, 200, { committed: true });
      }
      return json(res, 404, { error: 'Not found' });
    }

    return json(res, 404, { error: 'Not found' });
  } catch (error) {
    console.error(`Server ${role} request ${req.method} ${req.url} failed: ${error.message}`);
    if (!res.headersSent) json(res, 503, { error: error.message || 'Operation failed', restartRequired: protocolFault });
  }
};

const server = tlsOptions ? https.createServer(tlsOptions, requestHandler) : http.createServer(requestHandler);

server.listen(ownPort, listenHost, () => {
  const scheme = tlsOptions ? 'https' : 'http';
  console.log(`Server ${role.toUpperCase()} listening on ${scheme}://${listenHost}:${ownPort}; secure operations ${ENABLED ? 'enabled by explicit gate' : 'disabled'}`);
  if (role === 'a' && operationsEnabled()) {
    // Allow B to bind its listener, then prepare one query without client data.
    void (async () => {
      for (let attempt = 0; attempt < 20 && operationsEnabled(); attempt++) {
        try { await ensurePreprocessing(); return; }
        catch (error) {
          if (!error.message.includes('ECONNREFUSED')) return;
          if (attempt < 19) await new Promise(resolve => setTimeout(resolve, 250));
        }
      }
    })();
  }
});





