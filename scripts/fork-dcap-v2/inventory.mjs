#!/usr/bin/env node
// Read-only discovery. Never signs, sends transactions, or changes registry files.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const [output, ...chainFilter] = process.argv.slice(2);
if (!output || fs.existsSync(output)) throw new Error('Usage: inventory.mjs NEW_OUTPUT.json [CHAIN_ID ...]');
const metadata = JSON.parse(fs.readFileSync(path.join(root, 'go-sdk/packages/godcap/registry/metadata.json')));
const registry = path.join(root, 'rust-crates/libraries/network-registry/deployment/current');
const signatures = new Map();
function selector(signature) {
  if (!signatures.has(signature)) signatures.set(signature,
    execFileSync('cast', ['sig', signature], {encoding: 'utf8', timeout: 10000}).trim());
  return signatures.get(signature);
}
const word = value => BigInt(value).toString(16).padStart(64, '0');
const address = hex => {
  if (!/^0x[0-9a-fA-F]{64}$/.test(hex)) throw new Error('Invalid ABI address');
  return '0x' + hex.slice(-40);
};
async function rpc(url, method, params) {
  if (!['eth_chainId', 'eth_getBlockByNumber', 'eth_getCode', 'eth_call'].includes(method))
    throw new Error('Non-read-only RPC is forbidden');
  const response = await fetch(url, {
    method: 'POST', headers: {'content-type': 'application/json'},
    body: JSON.stringify({jsonrpc: '2.0', id: 1, method, params}),
    signal: AbortSignal.timeout(15000),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const payload = await response.json();
  if (payload.error) throw new Error(JSON.stringify(payload.error));
  if (payload.result === undefined) throw new Error('Missing JSON-RPC result');
  return payload.result;
}
async function inspect(network) {
  const id = String(network.chain_id);
  const contracts = JSON.parse(fs.readFileSync(path.join(registry, id, 'dcap.json')));
  const item = {chainId: network.chain_id, name: network.name, contracts, attempts: [], status: 'unreachable'};
  for (const url of network.rpc_endpoints) {
    try {
      const actual = Number(BigInt(await rpc(url, 'eth_chainId', [])));
      if (actual !== network.chain_id) throw new Error(`Wrong chain ID: ${actual}`);
      const block = await rpc(url, 'eth_getBlockByNumber', ['latest', false]);
      if (!block?.hash) throw new Error('Missing block');
      item.rpc = url; // Only public endpoints from the checked-in metadata are used.
      item.block = {number: Number(BigInt(block.number)), hex: block.number, hash: block.hash, timestamp: Number(BigInt(block.timestamp))};
      item.status = 'partial';
      const at = block.number;
      const call = (to, signature, args = '') => rpc(url, 'eth_call', [{to, data: selector(signature) + args}, at]);
      item.readErrors = [];
      async function read(label, fn) {
        try { return await fn(); }
        catch (error) { item.readErrors.push({field: label, error: error.message}); return null; }
      }
      const fee = contracts.AutomataDcapAttestationFee;
      const router = contracts.PCCSRouter;
      item.feeCodeBytes = await read('feeCode', async () => ((await rpc(url, 'eth_getCode', [fee, at])).length - 2) / 2);
      item.feeOwner = await read('feeOwner', async () => address(await call(fee, 'owner()')));
      item.router = {};
      for (const key of ['owner', 'tcbEvalDaoAddr', 'pcsDaoAddr', 'pckDaoAddr', 'pckHelperAddr', 'crlHelperAddr', 'fmspcTcbHelperAddr']) {
        item.router[key] = await read(`router.${key}`, async () => address(await call(router, key + '()')));
      }
      item.backends = {};
      for (const [name, kind] of [['risc0', 1], ['sp1', 2], ['pico', 3]]) {
        const config = item.backends[name] = {};
        config.defaultVerifier = await read(`${name}.defaultVerifier`, async () => address(await call(fee, 'zkVerifier(uint8)', word(kind))));
        config.defaultProgramId = await read(`${name}.defaultProgramId`, () => call(fee, 'programIdentifier(uint8)', word(kind)));
        config.programIdsAbi = await read(`${name}.programIds`, () => call(fee, 'programIdentifiers(uint8)', word(kind)));
        if (config.defaultVerifier && config.defaultVerifier !== '0x' + '0'.repeat(40)) {
          config.verifierCodeBytes = await read(`${name}.code`, async () => ((await rpc(url, 'eth_getCode', [config.defaultVerifier, at])).length - 2) / 2);
        }
      }
      const confirm = await rpc(url, 'eth_getBlockByNumber', [at, false]);
      if (confirm?.hash !== block.hash) throw new Error('Pinned block hash changed during inventory');
      item.status = item.readErrors.length ? 'partial' : 'snapshot';
      break;
    } catch (error) {
      item.attempts.push({rpc: url, error: error.message});
      // Discard partial state before trying a different endpoint.
      for (const key of ['rpc', 'block', 'readErrors', 'feeCodeBytes', 'feeOwner', 'router', 'backends']) delete item[key];
      item.status = 'unreachable';
    }
  }
  console.log(JSON.stringify({chainId: item.chainId, status: item.status, block: item.block?.number,
    backends: item.backends && Object.fromEntries(Object.entries(item.backends).map(([k,v]) => [k,v.defaultVerifier])),
    errors: item.readErrors?.length || item.attempts}));
  return item;
}
const networks = Object.values(metadata).filter(n => fs.existsSync(path.join(registry, String(n.chain_id), 'dcap.json')))
  .filter(n => !chainFilter.length || chainFilter.includes(String(n.chain_id)));
if (!networks.length) throw new Error('No registered target networks selected');
const results = [];
// Bound public-RPC load. These are independent read-only requests, not proving jobs.
let next = 0;
await Promise.all(Array.from({length: Math.min(3, networks.length)}, async () => {
  while (next < networks.length) results.push(await inspect(networks[next++]));
}));
results.sort((a,b) => a.chainId-b.chainId);
fs.writeFileSync(output, JSON.stringify({schema: 1, capturedAt: new Date().toISOString(),
  scope: 'Initial default configuration only; route event history and full release inventory remain required', networks: results}, null, 2) + '\n', {flag: 'wx'});
console.log(`Saved ${results.length} network records: ${output}`);
