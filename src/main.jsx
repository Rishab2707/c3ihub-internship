import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

const A = import.meta.env.VITE_DUORAM_SERVER_A || 'http://127.0.0.1:4101';
const B = import.meta.env.VITE_DUORAM_SERVER_B || 'http://127.0.0.1:4102';
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', '[::1]', 'localhost']);

function endpointTransportError(endpoint) {
  try {
    const url = new URL(endpoint);
    if (url.protocol === 'https:' || (url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname))) return null;
    return 'Remote server endpoints must use HTTPS.';
  } catch {
    return 'Server endpoint URL is invalid.';
  }
}

async function request(url, method = 'GET', payload, resultToken) {
  const response = await fetch(url, {
    method,
    headers: {
      ...(payload ? { 'content-type': 'application/json' } : {}),
      ...(resultToken ? { 'x-duoram-result-token': resultToken } : {}),
    },
    body: payload ? JSON.stringify(payload) : undefined,
  });
  const data = await response.json();
  if (response.status === 202) return { pending: true };
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  if (data.error) throw new Error(data.error);
  return data;
}

function xorShareBits(index, width) {
  const random = crypto.getRandomValues(new Uint8Array(width));
  const share0 = Array.from(random, byte => byte & 1);
  const share1 = share0.map((bit, position) => bit ^ ((index >>> position) & 1));
  return [share0, share1];
}

function randomBit() { return crypto.getRandomValues(new Uint8Array(1))[0] & 1; }
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

function App() {
  const [index, setIndex] = useState('0');
  const [value, setValue] = useState('1');
  const [databaseSize, setDatabaseSize] = useState(2 ** 16);
  const [domainBits, setDomainBits] = useState(16);
  const [enabled, setEnabled] = useState(false);
  const [status, setStatus] = useState('Checking servers…');
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const transportError = endpointTransportError(A) || endpointTransportError(B);
    if (transportError) {
      setEnabled(false);
      setStatus(transportError);
      return;
    }
    let active = true;
    let timer;
    function refresh() {
      Promise.all([request(`${A}/api/status`), request(`${B}/api/status`)])
      .then(([a, b]) => {
        if (!active) return;
        const paired = a.role === 'a' && b.role === 'b' && a.size === b.size && a.domainBits === b.domainBits;
        const ready = paired && a.operationsEnabled && b.operationsEnabled;
        setDatabaseSize(a.size);
        setDomainBits(a.domainBits);
        setEnabled(ready && a.preprocessing?.ready > 0);
        setStatus(!paired ? 'Configure one server A endpoint and one server B endpoint with matching database sizes' :
          ready ? `Both servers ready · ${a.size.toLocaleString()} bits · ${a.preprocessing?.ready ? 'Next access prepared' : 'Preparing next access'}` :
            a.restartRequired || b.restartRequired ? 'Restart both servers together' : 'Protocol validation gate is closed');
      })
      .catch(() => { if (active) { setEnabled(false); setStatus('Start both backend servers to connect'); } })
      .finally(() => { if (active) timer = setTimeout(refresh, 2000); });
    }
    refresh();
    return () => { active = false; clearTimeout(timer); };
  }, []);

  async function readServerShare(sessionId, resultToken) {
    const until = Date.now() + 120_000;
    while (Date.now() < until) {
      const response = await request(`${B}/api/result/${sessionId}`, 'GET', undefined, resultToken);
      if (!response.pending) return response;
      await pause(250);
    }
    throw new Error('Timed out waiting for the second server result');
  }

  async function run(operation) {
    setResult(null);
    const requestedIndex = Number(index);
    const requestedValue = Number(value);
    if (!Number.isInteger(requestedIndex) || requestedIndex < 0 || requestedIndex >= databaseSize) {
      setResult({ error: `Enter an index from 0 to ${databaseSize - 1}.` });
      return;
    }
    if (operation === 'insert' && ![0, 1].includes(requestedValue)) {
      setResult({ error: 'Inserted value must be 0 or 1.' });
      return;
    }

    setBusy(true);
    try {
      const sessionId = crypto.randomUUID();
      const resultToken = Array.from(crypto.getRandomValues(new Uint8Array(32)),
        byte => byte.toString(16).padStart(2, '0')).join('');
      const [indexShareA, indexShareB] = xorShareBits(requestedIndex, domainBits);
      const valueShareA = operation === 'insert' ? randomBit() : 0;
      const valueShareB = operation === 'insert' ? requestedValue ^ valueShareA : 0;
      await request(`${B}/api/share`, 'POST', { sessionId, indexShareBits: indexShareB, valueShare: valueShareB, resultToken });
      const data = await request(`${A}/api/${operation}`, 'POST', {
        sessionId,
        indexShareBits: indexShareA,
        ...(operation === 'insert' ? { valueShare: valueShareA } : {}),
      });
      if (operation === 'access') {
        const secondShare = await readServerShare(sessionId, resultToken);
        if ((data.validityShare ^ secondShare.validityShare) !== 1) {
          throw new Error('The shared index is outside the database.');
        }
        setResult({ operation: 'Access', index: requestedIndex, value: data.share ^ secondShare.share });
      } else {
        const secondShare = await readServerShare(sessionId, resultToken);
        if ((data.validityShare ^ secondShare.validityShare) !== 1) {
          throw new Error('The shared index is outside the database.');
        }
        setResult({ operation: 'Insert', index: requestedIndex, value: requestedValue });
      }
    } catch (error) {
      setResult({ error: error.message });
    } finally {
      setBusy(false);
    }
  }

  return <main className="shell">
    <header><div className="eyebrow">DUORAM · TWO SERVER PROTOTYPE</div><h1>Oblivious bit store</h1><p className="intro">The browser splits each index into XOR shares and sends one share to each server.</p></header>
    <section className="card">
      <div className="status"><span className={enabled ? 'dot online' : 'dot'} />{status}</div>
      <label>Database index <span>0–{(databaseSize - 1).toLocaleString()}</span><input type="number" min="0" max={databaseSize - 1} value={index} onChange={event => setIndex(event.target.value)} /></label>
      <label>Bit value <span>0 or 1 · used for insert</span><select value={value} onChange={event => setValue(event.target.value)}><option value="0">0</option><option value="1">1</option></select></label>
      <div className="actions"><button disabled={!enabled || busy} onClick={() => run('access')}>{busy ? 'Working…' : 'Access bit'}</button><button className="secondary" disabled={!enabled || busy} onClick={() => run('insert')}>Insert / replace</button></div>
      {result && <div className={`result ${result.error ? 'error' : ''}`}>{result.error || <><strong>{result.operation} complete</strong><span>Index {result.index} contains bit <b>{result.value}</b></span></>}</div>}
    </section>
  </main>;
}

createRoot(document.getElementById('root')).render(<App />);
