import { randomBytes } from 'node:crypto';
import { evaluateDuoramDpfValues } from './duoram-dpf.js';
import { BLOCK_BYTES, isBlockHex } from '../../shared/block-format.js';

export function createHelperState(size) {
  const domainBits = Math.max(1, Math.ceil(Math.log2(size)));
  const blinds = [new Uint8Array(size * BLOCK_BYTES), new Uint8Array(size * BLOCK_BYTES)];
  let version = 0, activeUpdate = null;
  const prepared = new Map(), usedPreprocessing = new Set(), sessions = new Map(), seenSessions = new Set();
  const uuid = value => typeof value === 'string' && /^[0-9a-f-]{36}$/i.test(value);
  function paired(entry, phase, party, contribution, finish) {
    let round = entry[phase];
    if (!round) {
      round = entry[phase] = { inputs: [], waiters: [] };
      round.timer = setTimeout(() => {
        for (const waiter of round.waiters) waiter?.reject(new Error('Helper round timed out; restart all servers'));
        round.failed = true;
      }, 120_000); round.timer.unref();
    }
    if (round.failed || round.inputs[party] !== undefined) throw new Error('Duplicate or expired helper contribution');
    round.inputs[party] = contribution;
    return new Promise((resolve, reject) => {
      round.waiters[party] = { resolve, reject };
      if (round.inputs[0] !== undefined && round.inputs[1] !== undefined) {
        clearTimeout(round.timer);
        try {
          const outputs = finish(round.inputs);
          round.waiters.forEach((waiter, p) => waiter.resolve(outputs[p]));
        } catch (error) {
          round.failed = true; round.waiters.forEach(waiter => waiter.reject(error));
        }
      }
    });
  }
  function projected(evaluation) {
    return { flags: evaluation.flags, values: evaluation.values };
  }
  return async function handle(path, body, party) {
    if (path === '/internal/preprocess') {
      if (body.databaseSize !== size || body.domainBits !== domainBits || body.key?.party !== party || body.key?.domainBits !== domainBits) {
        throw new Error('Helper preprocessing configuration mismatch');
      }
      let item = prepared.get(body.id);
      if (!item) {
        if (usedPreprocessing.has(body.id) || prepared.size >= 4 || usedPreprocessing.size >= 100_000) throw new Error('Helper preprocessing unavailable');
        item = { shares: [] }; prepared.set(body.id, item); usedPreprocessing.add(body.id);
      }
      if (item.shares[party]) throw new Error('Duplicate helper key');
      // Only component Blind0/A and Blind1/B are supplied. No Read key.
      item.shares[party] = projected(evaluateDuoramDpfValues(body.key));
      return { registered: true };
    }
    if (path === '/internal/discard') {
      usedPreprocessing.add(body.id);
      prepared.delete(body.id);
      return { discarded: true };
    }
    if (path === '/internal/read') {
      if (!uuid(body.preprocessingId) || !Number.isInteger(body.shift) || body.shift < 0 || body.shift >= 2 ** domainBits ||
          !['access', 'insert'].includes(body.operation) || body.version !== version || (activeUpdate && activeUpdate !== body.id)) {
        throw new Error('Helper read state mismatch; restart all servers');
      }
      let entry = sessions.get(body.id);
      if (!entry) {
        const material = prepared.get(body.preprocessingId);
        if (seenSessions.has(body.id) || !material?.shares[0] || !material.shares[1] || sessions.size >= 128 || seenSessions.size >= 100_000) {
          throw new Error('Fresh helper preprocessing unavailable');
        }
        prepared.delete(body.preprocessingId); seenSessions.add(body.id);
        entry = { material, preprocessingId: body.preprocessingId, operation: body.operation, shift: body.shift, version };
        sessions.set(body.id, entry);
        if (body.operation === 'insert') activeUpdate = body.id;
      }
      if (entry.preprocessingId !== body.preprocessingId || entry.operation !== body.operation || entry.shift !== body.shift || entry.version !== body.version) {
        throw new Error('Helper read contributions disagree');
      }
      return paired(entry, 'read', party, true, () => {
        const rho = randomBytes(BLOCK_BYTES);
        const gamma0 = Buffer.from(rho), gamma1 = Buffer.from(rho);
        for (let i = 0; i < size; i++) {
          const mask0 = -entry.material.shares[1].flags[i ^ entry.shift];
          const mask1 = -entry.material.shares[0].flags[i ^ entry.shift];
          for (let byte = 0; byte < BLOCK_BYTES; byte++) {
            gamma0[byte] ^= blinds[0][i * BLOCK_BYTES + byte] & mask0;
            gamma1[byte] ^= blinds[1][i * BLOCK_BYTES + byte] & mask1;
          }
        }
        if (entry.operation === 'access') sessions.delete(body.id);
        return [{ gamma: gamma0.toString('hex'), version }, { gamma: gamma1.toString('hex'), version }];
      });
    }
    if (path === '/internal/stage-update') {
      const entry = sessions.get(body.id);
      if (!entry || entry.operation !== 'insert' || entry.read?.inputs.length !== 2 || entry.version !== version ||
          !Array.isArray(body.finalBlinds) || body.finalBlinds.length !== 2 || !body.finalBlinds.every(isBlockHex)) {
        throw new Error('Helper update state unavailable');
      }
      return paired(entry, 'update', party, body.finalBlinds, inputs => {
        if (JSON.stringify(inputs[0]) !== JSON.stringify(inputs[1])) throw new Error('Helper update corrections disagree');
        entry.staged = blinds.map((blind, p) => {
          const correction = Buffer.from(inputs[0][p], 'hex');
          const dpf = entry.material.shares[p];
          return blind.map((byte, offset) => {
            const i = Math.floor(offset / BLOCK_BYTES), b = offset % BLOCK_BYTES;
            return byte ^ dpf.values[i ^ entry.shift][b] ^ (-dpf.flags[i ^ entry.shift] & correction[b]);
          });
        });
        return [{ staged: true }, { staged: true }];
      });
    }
    if (path === '/internal/commit') {
      const entry = sessions.get(body.id);
      if (party !== 0 || !entry) throw new Error('Helper commit unavailable');
      if (entry.committed) return { committed: true, version: entry.version + 1 };
      if (!entry.staged || entry.version !== version || activeUpdate !== body.id) throw new Error('Helper commit state mismatch');
      blinds[0].set(entry.staged[0]); blinds[1].set(entry.staged[1]);
      version++; activeUpdate = null; entry.committed = true;
      delete entry.staged; delete entry.material;
      const timer = setTimeout(() => sessions.delete(body.id), 5 * 60_000); timer.unref();
      return { committed: true, version };
    }
    throw new Error('Unknown helper route');
  };
}
