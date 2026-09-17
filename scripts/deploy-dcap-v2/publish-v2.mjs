#!/usr/bin/env node
// Read-only RPC; local registry writes only after confirmed live readback.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const zero = '0x' + '0'.repeat(40);
const zeroId = '0x' + '0'.repeat(64);
const same = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();
const ensure = (ok, message) => { if (!ok) throw new Error(message); };
const sha = data => createHash('sha256').update(data).digest('hex');
const json = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const encoded = value => JSON.stringify(value, null, 2) + '\n';
const addr = value => ensure(/^0x[0-9a-f]{40}$/i.test(value) && !same(value, zero), 'Invalid/nonzero address required');
const componentNames = ['tcbEvalDaoAddr', 'pcsDaoAddr', 'pckDaoAddr', 'pckHelperAddr', 'crlHelperAddr', 'fmspcTcbHelperAddr'];
const contractKeys = ['AutomataDcapAttestationFeeV2', 'PCCSRouterV2', 'PCKHelperV2',
  'V3QuoteVerifierV2', 'V4QuoteVerifierV2', 'V5QuoteVerifierV2'];

// Keep provider diagnostics without logging the endpoint or its credentials.
export function createRpcRequest(url, fetchImpl = fetch) {
  let endpoint;
  try { endpoint = new URL(url); } catch { throw new Error('Invalid RPC URL'); }
  ensure(['http:', 'https:'].includes(endpoint.protocol), 'HTTP(S) RPC URL required');
  const decode = value => { try { return decodeURIComponent(value); } catch { return value; } };
  const secrets = [url, endpoint.username, endpoint.password, ...endpoint.searchParams.values(),
    ...endpoint.pathname.split('/').filter(value => value.length >= 8)]
    .flatMap(value => [value, decode(value)]).filter(Boolean).sort((a, b) => b.length - a.length);
  const redact = value => {
    let text = String(value);
    for (const secret of secrets) text = text.split(secret).join('[REDACTED]');
    return text.replace(/https?:\/\/[^\s"'<>]+/gi, '[REDACTED_URL]').slice(0, 2048);
  };
  let id = 0;
  return async (method, params = [], context = '') => {
    ensure(['eth_chainId', 'eth_getBlockByNumber', 'eth_getCode', 'eth_call', 'eth_getStorageAt', 'eth_getTransactionReceipt'].includes(method), 'Read-only RPC required');
    const target = method === 'eth_call'
      ? ` to=${params[0]?.to} selector=${params[0]?.data?.slice(0, 10)} block=${params[1]}`
      : '';
    const label = `RPC ${method}${target}${context ? ` ${context}` : ''}`;
    try {
      const response = await fetchImpl(url, {method: 'POST', headers: {'content-type': 'application/json'},
        body: JSON.stringify({jsonrpc: '2.0', id: ++id, method, params}), signal: AbortSignal.timeout(30000)});
      let body;
      try { body = await response.json(); } catch { throw new Error(`HTTP ${response.status}: invalid JSON response`); }
      if (body?.error) throw new Error(`HTTP ${response.status}: ${JSON.stringify(body.error)}`);
      ensure(response.ok, `HTTP ${response.status}`);
      ensure(body && body.result !== undefined, 'Missing JSON-RPC result');
      return body.result;
    } catch (error) {
      throw new Error(redact(`${label}: ${error.message}${error.cause?.code ? ` (${error.cause.code})` : ''}`));
    }
  };
}

export function validatePlan(p) {
  ensure(Number.isSafeInteger(p.chainId) && p.chainId > 0, 'Invalid chain ID');
  ensure(p.status === 'TEST_ONLY', 'This publisher is for isolated test deployments, not release promotion');
  ensure(/^[0-9a-f]{40}$/.test(p.sourceCommit), 'Pin source commit');
  addr(p.owner); addr(p.legacyFee); addr(p.legacyRouter); addr(p.p256);
  ensure(Array.isArray(p.evaluations) && p.evaluations.length > 0, 'Missing evaluation inventory');
  p.evaluations.forEach((n, i) => ensure(Number.isInteger(n) && n > 0 && n <= 0xffffffff
    && (i === 0 || n > p.evaluations[i - 1]), 'Evaluation inventory must be sorted/unique'));
  ensure(Array.isArray(p.programs), 'Explicit programs array required (empty means raw-only)');
  const seen = new Set();
  for (const program of p.programs) {
    ensure([1, 2].includes(program.backend) && !seen.has(program.backend), 'Unsupported/duplicate backend');
    seen.add(program.backend);
    ensure(/^0x[0-9a-f]{64}$/i.test(program.id) && !same(program.id, zeroId), 'Invalid native ID');
    ensure(/^0x[0-9a-f]{8}$/i.test(program.proofSelector), 'Invalid proof selector');
    addr(program.verifier);
    // Provenance references are operator-supplied, not a claim of proof acceptance.
    ensure(program.buildSourceCommit === p.sourceCommit && /^[0-9a-f]{64}$/.test(program.evidenceSha256)
      && /^[0-9a-f]{64}$/.test(program.artifactSha256), 'Missing matching build provenance');
  }
}

export function makeDocuments(p, legacyDcap, legacyPccs) {
  const contracts = p.contracts;
  ensure(contracts && JSON.stringify(Object.keys(contracts).sort()) === JSON.stringify([...contractKeys].sort()), 'Exactly six V2 contract keys required');
  contractKeys.forEach(k => addr(contracts[k]));
  ensure(new Set(contractKeys.map(k => contracts[k].toLowerCase())).size === 6, 'Six distinct contracts required');
  ensure(same(legacyDcap.AutomataDcapAttestationFee, p.legacyFee)
    && same(legacyDcap.PCCSRouter, p.legacyRouter), 'Legacy registry does not match plan');
  const oldAddresses = new Set([...Object.values(legacyDcap), ...Object.values(legacyPccs)]
    .filter(v => typeof v === 'string').map(v => v.toLowerCase()));
  contractKeys.forEach(k => ensure(!oldAddresses.has(contracts[k].toLowerCase()), 'New address aliases existing deployment'));
  // Preserve legacy keys: consumers must explicitly select V2 keys, including the Router.
  const dcap = {...legacyDcap, ...contracts};
  const pccs = {...legacyPccs, PCKHelperV2: contracts.PCKHelperV2};
  // Publish only the evaluation inventory actually configured on the isolated Router.
  for (const key of Object.keys(pccs)) {
    const match = key.match(/_tcbeval_(\d+)$/);
    if (match && !p.evaluations.includes(Number(match[1]))) delete pccs[key];
  }
  return {dcap, pccs};
}

export function updatePccsDeployment(previous, helper) {
  addr(helper);
  return {...previous, PCKHelperV2: helper};
}

// Caller supplies a block-pinned RPC adapter; this function never sends transactions.
export async function readLegacy(p, rpc) {
  const {call, code} = rpc;
  const router = {}, evaluations = {}, backends = {};
  for (const name of componentNames) {
    router[name] = await call(p.legacyRouter, `${name}()`, 'address');
    addr(router[name]); ensure(await code(router[name]) !== '0x', 'Legacy dependency has no code');
  }
  for (const n of p.evaluations) {
    evaluations[n] = {};
    for (const name of ['qeIdDaoVersionedAddr', 'fmspcTcbDaoVersionedAddr']) {
      const dao = await call(p.legacyRouter, `${name}(uint32)`, 'address', n);
      addr(dao); ensure(await code(dao) !== '0x', 'Missing versioned DAO');
      ensure(Number(await call(dao, 'TCB_EVALUATION_NUMBER()', 'uint32')) === n, 'DAO evaluation mismatch');
      evaluations[n][name] = dao;
    }
  }
  const verifiers = {};
  for (const version of [3, 4, 5]) {
    const verifier = await call(p.legacyFee, 'quoteVerifiers(uint16)', 'address', version);
    addr(verifier);
    ensure(same(await call(verifier, 'pccsRouter()', 'address'), p.legacyRouter), 'Legacy Fee/Router mismatch');
    verifiers[version] = verifier;
  }
  // Older deployed Fees reject enum value 3 (Pico), even for view getters.
  // Snapshot only the rollout backends. Do not relax verifyNew's Pico checks.
  for (const backend of [1, 2]) {
    const verifier = await call(p.legacyFee, 'zkVerifier(uint8)', 'address', backend);
    backends[backend] = {verifier, code: same(verifier, zero) ? '0x' : await code(verifier),
      defaultId: await call(p.legacyFee, 'programIdentifier(uint8)', 'bytes32', backend),
      ids: await call(p.legacyFee, 'programIdentifiers(uint8)', 'bytes32[]', backend)};
  }
  for (const program of p.programs) {
    ensure(same(program.verifier, backends[program.backend].verifier)
      && backends[program.backend].code !== '0x', 'Backend expansion is not allowed');
  }
  return {router, evaluations, backends, verifiers,
    feeOwner: await call(p.legacyFee, 'owner()', 'address'),
    routerOwner: await call(p.legacyRouter, 'owner()', 'address'),
    feeBp: String(await call(p.legacyFee, 'getBp()', 'uint16')),
    feeCode: await code(p.legacyFee), routerCode: await code(p.legacyRouter)};
}

export async function verifyNew(p, legacy, documents, rpc) {
  const {call, code, storage} = rpc;
  const c = p.contracts, router = c.PCCSRouterV2, fee = c.AutomataDcapAttestationFeeV2;
  const codeHashes = {}, resolvers = new Set();
  for (const key of contractKeys) {
    const runtime = await code(c[key]); ensure(runtime !== '0x', `${key} has no code`);
    await rpc.verifyArtifact(key, runtime);
    codeHashes[key] = sha(Buffer.from(runtime.slice(2), 'hex'));
  }
  for (const target of [router, fee]) ensure(same(await call(target, 'owner()', 'address'), p.owner), 'New owner mismatch');
  ensure(String(await call(fee, 'getBp()', 'uint16')) === legacy.feeBp, 'Fee basis points mismatch');
  ensure(await call(fee, 'zkV2Paused()', 'bool') === (p.programs.length === 0), 'Unexpected ZK pause state');
  for (const name of componentNames) {
    ensure(same(await call(router, `${name}()`, 'address'),
      name === 'pckHelperAddr' ? c.PCKHelperV2 : legacy.router[name]), 'Router dependency mismatch');
  }
  // The adapter checks the exact local Router runtime before relying on its storage layout.
  await rpc.verifyRouterLayout(router);
  const packed = BigInt(await storage(router, '0x1'));
  ensure((packed & 255n) === 1n && ((packed >> 8n) & ((1n << 160n) - 1n))
    === BigInt(legacy.router.tcbEvalDaoAddr), 'Router restriction/layout mismatch');
  for (const target of [fee, c.V3QuoteVerifierV2, c.V4QuoteVerifierV2, c.V5QuoteVerifierV2]) {
    ensure(await rpc.authorized(router, target), 'Missing Router reader authorization');
  }
  for (const version of [3, 4, 5]) {
    const verifier = c[`V${version}QuoteVerifierV2`];
    ensure(same(await call(fee, 'quoteVerifiers(uint16)', 'address', version), verifier), 'Fee verifier mismatch');
    ensure(Number(await call(verifier, 'quoteVersion()', 'uint16')) === version, 'Quote version mismatch');
    ensure(same(await call(verifier, 'pccsRouter()', 'address'), router), 'Verifier uses wrong Router');
    ensure(same(await call(verifier, 'P256_VERIFIER()', 'address'), p.p256), 'P256 mismatch');
  }
  const checkResolver = async dao => {
    const resolver = await call(dao, 'resolver()', 'address'); addr(resolver);
    ensure(await code(resolver) !== '0x', 'Missing resolver');
    ensure(await call(resolver, 'isAuthorizedCaller(address)', 'bool', router), 'New Router lacks Storage reader permission');
    resolvers.add(resolver);
  };
  for (const name of ['tcbEvalDaoAddr', 'pcsDaoAddr', 'pckDaoAddr']) await checkResolver(legacy.router[name]);
  const pj = documents.pccs;
  const selected = (keys) => keys.map(k => pj[k]).find(Boolean);
  for (const [name, keys] of [
    ['tcbEvalDaoAddr', ['AutomataTcbEvalDaoCrlV2', 'AutomataTcbEvalDao']],
    ['pcsDaoAddr', ['AutomataPcsDaoV2', 'AutomataPcsDao']],
    ['pckDaoAddr', ['AutomataPckDaoV2', 'AutomataPckDao']]]) {
    ensure(same(selected(keys), legacy.router[name]), 'PCCS registry is stale; reconcile before publishing');
  }
  for (const n of p.evaluations) {
    for (const [name, keys] of [
      ['qeIdDaoVersionedAddr', [`AutomataEnclaveIdentityDaoVersionedCrlV2_tcbeval_${n}`, `AutomataEnclaveIdentityDaoVersioned_tcbeval_${n}`]],
      ['fmspcTcbDaoVersionedAddr', [`AutomataFmspcTcbDaoVersionedV2CrlV2_tcbeval_${n}`, `AutomataFmspcTcbDaoVersionedV2_tcbeval_${n}`, `AutomataFmspcTcbDaoVersioned_tcbeval_${n}`]]]) {
      const dao = await call(router, `${name}(uint32)`, 'address', n);
      ensure(same(dao, legacy.evaluations[n][name]) && same(dao, selected(keys)), 'Versioned DAO registry mismatch');
      await checkResolver(dao);
    }
  }
  for (const backend of [1, 2, 3]) {
    const program = p.programs.find(item => item.backend === backend);
    const ids = await call(fee, 'programIdentifiersV2(uint8)', 'bytes32[]', backend);
    ensure(ids.length === (program ? 1 : 0), 'Unexpected V2 ID inventory');
    ensure(same(await call(fee, 'programIdentifierV2(uint8)', 'bytes32', backend), program?.id ?? zeroId), 'V2 default ID mismatch');
    if (program) {
      ensure(same(ids[0], program.id), 'V2 ID mismatch');
      for (const selector of ['0x00000000', program.proofSelector]) {
        ensure(same(await call(fee, 'zkVerifierV2(uint8,bytes4)', 'address', backend, selector), program.verifier), 'V2 proof route mismatch');
      }
    }
  }
  return {runtimeSha256: codeHashes, readerStorages: [...resolvers]};
}

async function main() {
  const [mode, planFile, snapshotFile, reportFile] = process.argv.slice(2);
  ensure(['snapshot', 'publish'].includes(mode) && planFile && snapshotFile
    && (mode === 'snapshot' || reportFile), 'Usage: publish-v2.mjs snapshot PLAN SNAPSHOT | publish PLAN SNAPSHOT NEW_REPORT');
  const p = json(planFile); validatePlan(p);
  const url = process.env.DCAP_RPC_URL; ensure(url, 'DCAP_RPC_URL required');
  const request = createRpcRequest(url);
  ensure(Number(BigInt(await request('eth_chainId'))) === p.chainId, 'Wrong RPC chain');
  // Require confirmed state; never publish simulation or pending addresses.
  const block = await request('eth_getBlockByNumber', ['finalized', false]);
  ensure(block?.hash && block?.number, 'RPC must provide finalized block');
  const cast = (...args) => execFileSync('cast', args, {encoding: 'utf8', maxBuffer: 8 * 1024 * 1024}).trim();
  const rpc = {
    call: async (to, sig, returns, ...args) => JSON.parse(cast('abi-decode', '--json', `f()(${returns})`,
      await request('eth_call', [{to, data: cast('calldata', sig, ...args.map(String))}, block.number],
        `function=${sig} args=${JSON.stringify(args)}`)))[0],
    code: to => request('eth_getCode', [to, block.number]),
    storage: (to, slot) => request('eth_getStorageAt', [to, slot, block.number]),
    verifyArtifact: async (key, runtime) => {
      const name = key === 'AutomataDcapAttestationFeeV2' ? key : key.replace(/V2$/, '');
      const artifact = json(path.join(root, `evm/out/${name}.sol/${name}.json`));
      const actual = Buffer.from(runtime.slice(2), 'hex');
      const expected = Buffer.from(artifact.deployedBytecode.object.replace(/^0x/, ''), 'hex');
      ensure(actual.length > 0 && actual.length <= 24576 && actual.length === expected.length, 'Invalid deployed runtime size');
      for (const refs of Object.values(artifact.deployedBytecode.immutableReferences ?? {})) {
        ensure(new Set(refs.map(r => actual.subarray(r.start, r.start + r.length).toString('hex'))).size === 1, 'Inconsistent immutables');
        for (const r of refs) { actual.fill(0, r.start, r.start + r.length); expected.fill(0, r.start, r.start + r.length); }
      }
      ensure(actual.equals(expected), `${key} runtime differs from local artifact`);
    },
    verifyRouterLayout: async to => {
      const artifact = json(path.join(root, 'evm/out/PCCSRouter.sol/PCCSRouter.json'));
      const expected = artifact.deployedBytecode.object;
      ensure(same(await rpc.code(to), expected.startsWith('0x') ? expected : '0x' + expected), 'Router runtime differs from local reviewed artifact');
    },
    authorized: async (router, reader) => BigInt(await rpc.storage(router,
      cast('keccak', cast('abi-encode', 'f(address,uint256)', reader, '0')))) === 1n,
  };
  const legacy = await readLegacy(p, rpc);
  const identity = {chainId: p.chainId, legacyFee: p.legacyFee, legacyRouter: p.legacyRouter,
    evaluations: p.evaluations, sourceCommit: p.sourceCommit};
  if (mode === 'snapshot') {
    fs.writeFileSync(snapshotFile, encoded({identity, block, legacy}), {flag: 'wx'});
    console.log('Read-only legacy snapshot saved. No deployment or registry writes.'); return;
  }
  const before = json(snapshotFile);
  ensure(JSON.stringify(before.identity) === JSON.stringify(identity), 'Snapshot/plan mismatch');
  ensure(BigInt(before.block.number) <= BigInt(block.number), 'Snapshot is newer than finalized readback');
  ensure((await request('eth_getBlockByNumber', [before.block.number, false]))?.hash === before.block.hash, 'Snapshot block changed');
  ensure(JSON.stringify(legacy) === JSON.stringify(before.legacy), 'Legacy configuration changed since snapshot');
  ensure(Array.isArray(p.transactions) && p.transactions.length >= 6, 'Deployment transaction inventory required');
  const receipts = [];
  for (const hash of p.transactions) {
    ensure(/^0x[0-9a-f]{64}$/i.test(hash), 'Invalid transaction hash');
    const receipt = await request('eth_getTransactionReceipt', [hash]);
    ensure(receipt && BigInt(receipt.status) === 1n && BigInt(receipt.blockNumber) <= BigInt(block.number)
      && BigInt(receipt.blockNumber) > BigInt(before.block.number), 'Transaction failed, unfinalized or predates snapshot');
    ensure((await request('eth_getBlockByNumber', [receipt.blockNumber, false]))?.hash === receipt.blockHash, 'Transaction block changed');
    receipts.push(receipt);
  }
  const registry = path.join(root, 'rust-crates/libraries/network-registry/deployment');
  const source = path.join(registry, 'current', String(p.chainId));
  const documents = makeDocuments(p, json(path.join(source, 'dcap.json')), json(path.join(source, 'onchain_pccs.json')));
  for (const key of contractKeys) ensure(receipts.some(r => same(r.contractAddress, p.contracts[key])), 'Missing direct deployment receipt for ' + key);
  const verified = await verifyNew(p, legacy, documents, rpc);
  const pccsPath = path.join(root, 'evm/lib/automata-on-chain-pccs/deployment', `${p.chainId}.json`);
  const originalPccs = fs.readFileSync(pccsPath, 'utf8');
  const pccsUpdate = updatePccsDeployment(JSON.parse(originalPccs), p.contracts.PCKHelperV2);
  const destination = path.join(registry, 'v2.0', String(p.chainId));
  // Iterations must explicitly archive/review the previous registry before replacement.
  ensure(!fs.existsSync(destination) && !fs.existsSync(reportFile), 'Output already exists; archive previous test deployment first');
  ensure((await request('eth_getBlockByNumber', [block.number, false]))?.hash === block.hash, 'Readback block changed');
  const report = {status: 'TEST_DEPLOYMENT_READBACK_PASS_NOT_PROOF_OR_RELEASE_ACCEPTANCE',
    plan: p, block, transactions: receipts, legacySnapshotSha256: sha(fs.readFileSync(snapshotFile)), ...verified,
    pccsDeploymentBefore: JSON.parse(originalPccs), currentPromoted: false};
  // Stage complete files before publishing the new directory; current/v1.1 are never written.
  const parent = path.dirname(destination);
  fs.mkdirSync(parent, {recursive: true});
  const stage = fs.mkdtempSync(path.join(parent, '.staging-'));
  fs.writeFileSync(path.join(stage, 'dcap.json'), encoded(documents.dcap));
  fs.writeFileSync(path.join(stage, 'onchain_pccs.json'), encoded(documents.pccs));
  fs.writeFileSync(path.join(stage, 'manifest.json'), encoded(report));
  ensure(fs.readFileSync(pccsPath, 'utf8') === originalPccs, 'PCCS registry changed concurrently');
  fs.writeFileSync(reportFile, encoded(report), {flag: 'wx'});
  fs.renameSync(stage, destination);
  // Additive key only. Existing PCKHelper and every other PCCS key are preserved.
  fs.writeFileSync(pccsPath, encoded(pccsUpdate));
  console.log(`Published TEST_ONLY ${destination}; added PCKHelperV2 to ${pccsPath}. current and ZK submodules unchanged.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
