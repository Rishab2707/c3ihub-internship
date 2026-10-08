import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const portA = Number(process.env.DUORAM_PORT_A || 4101);
const portB = Number(process.env.DUORAM_PORT_B || 4102);
const dealerPort = Number(process.env.DUORAM_PORT_DEALER || 4103);
const dealerTokens = [randomBytes(32).toString('hex'), randomBytes(32).toString('hex')];
const clientPort = 5173;
if (![portA, portB, dealerPort].every(port => Number.isInteger(port) && port > 0 && port <= 65535) ||
    new Set([portA, portB, dealerPort, clientPort]).size !== 4) throw new Error('Choose distinct valid server and dealer ports, different from 5173');
const common = {
  ...process.env,
  NODE_ENV: 'test', DUORAM_TEST_ENABLE_ORAM: '1', ENABLE_ONLINE_ORAM: '1',
  DUORAM_HOST: '127.0.0.1', DUORAM_PEER_TOKEN: randomBytes(32).toString('hex'),
  DUORAM_PORT_A: String(portA), DUORAM_PORT_B: String(portB),
  DUORAM_PORT_DEALER: String(dealerPort), DUORAM_DEALER_URL: `http://127.0.0.1:${dealerPort}`,
  DUORAM_DEALER_TOKEN_A: '', DUORAM_DEALER_TOKEN_B: '',
  DUORAM_TLS_KEY_PATH: '', DUORAM_TLS_CERT_PATH: '', DUORAM_TLS_CA_PATH: '',
  DUORAM_ALLOWED_ORIGINS: `http://127.0.0.1:${clientPort},http://localhost:${clientPort}`,
};
console.log('Local demo: two database servers and an online blinding helper on loopback HTTP.');
console.log(`Open http://127.0.0.1:${clientPort}; select third-party or OT triples for DPF generation.`);
const children = [];
let stopping = false;
function stop(code) {
  if (stopping) return;
  stopping = true;
  process.exitCode = code;
  for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill();
}
function launch(args, env) {
  const child = spawn(process.execPath, args, { cwd: root, env, stdio: 'inherit' });
  children.push(child);
  child.on('error', error => { console.error(error.message); stop(1); });
  child.on('exit', code => { if (!stopping) stop(code || 1); });
}
launch(['server/dealer.js'], { ...common, DUORAM_DEALER_TOKEN_A: dealerTokens[0], DUORAM_DEALER_TOKEN_B: dealerTokens[1] });
for (const role of ['a', 'b']) launch(['server/server.js', role], {
  ...common, DUORAM_PEER_URL: `http://127.0.0.1:${role === 'a' ? portB : portA}`,
  [role === 'a' ? 'DUORAM_DEALER_TOKEN_A' : 'DUORAM_DEALER_TOKEN_B']: dealerTokens[role === 'a' ? 0 : 1],
});
launch(['node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', String(clientPort), '--strictPort'], {
  ...process.env, NODE_ENV: 'development',
  VITE_DUORAM_SERVER_A: `http://127.0.0.1:${portA}`, VITE_DUORAM_SERVER_B: `http://127.0.0.1:${portB}`,
});
process.on('SIGINT', () => stop(0));
process.on('SIGTERM', () => stop(0));
