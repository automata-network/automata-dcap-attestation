#!/usr/bin/env node
// Read-only RPC; local registry writes only after confirmed live readback.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {replacement, registryHashes, registryFiles, validateReplacement, readReplacementState, verifyReplacement, frozenRoute} from './replacement.mjs';

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
const contractKeys = ['AutomataDcapAttestationV2', 'PCCSRouterV2', 'PCKHelperV2',
  'V3QuoteVerifierV2', 'V4QuoteVerifierV2', 'V5QuoteVerifierV2'];
export const pendingSp1Verifier = 'DEPLOY_SP1_GROTH16_V6_1';
const sp1VerifierHash = '0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696';

export function requireNewPublication(chainId, reportFile) {
  const destination = path.join(root, 'rust-crates/libraries/network-registry/deployment/v2.0', String(chainId));
  ensure(!fs.existsSync(destination) && !fs.existsSync(reportFile),
    'Output already exists; review/archive the previous test deployment before pinning source and broadcasting');
  return destination;
}

export function requirePublication(p, reportFile) {
  if (!replacement(p)) return requireNewPublication(p.chainId, reportFile);
  const destination = path.join(root, 'rust-crates/libraries/network-registry/deployment/v2.0', String(p.chainId));
  ensure(!fs.existsSync(reportFile), 'Readback report already exists; inspect completed/partial publication');
  ensure(JSON.stringify(registryHashes(destination)) === JSON.stringify(p.sourceRegistryHashes),
    'Source V2 registry changed; inspect checkpoint before continuing');
  ensure(!fs.existsSync(path.join(root, 'rust-crates/libraries/network-registry/deployment/history', String(p.chainId), p.legacyFee.toLowerCase())),
    'Source deployment already archived; inspect completed/partial publication');
  return destination;
}

export function readBuildArtifact(name, execute = execFileSync) {
  const cwd = path.join(root, 'evm');
  const {out} = JSON.parse(execute('forge', ['config', '--json'], {cwd, encoding: 'utf8'}));
  ensure(typeof out === 'string' && out.length > 0, 'Missing Foundry artifact directory');
  return json(path.resolve(cwd, out, `${name}.sol`, `${name}.json`));
}

// Reused Routers can have different source-metadata hashes after dependency-only commits.
// Never relax executable-bytecode comparison, or the strict comparison for NEW deployments.
export function executableRuntime(hex) {
  const bytes = Buffer.from(hex.replace(/^0x/, ''), 'hex');
  ensure(bytes.length > 2, 'Invalid runtime');
  const length = bytes.readUInt16BE(bytes.length - 2);
  const start = bytes.length - length - 2;
  ensure(length > 0 && start > 0 && (bytes[start] & 0xe0) === 0xa0, 'Invalid Solidity metadata footer');
  return bytes.subarray(0, start);
}

export function validateBuildSources(p, execute = execFileSync) {
  for (const commit of new Set(p.programs.map(program => program.buildSourceCommit))) {
    try {
      execute('git', ['merge-base', '--is-ancestor', commit, p.sourceCommit], {cwd: root, stdio: 'pipe'});
      execute('git', ['diff', '--exit-code', commit, p.sourceCommit, '--', 'rust-crates',
        ':(exclude)rust-crates/libraries/network-registry/deployment', 'scripts/fork-dcap-v2'], {cwd: root, stdio: 'pipe'});
    } catch {
      throw new Error(`Build ${commit} is not an ancestor with unchanged Rust/proving inputs; use reviewed new artifacts, never relabel provenance`);
    }
  }
}

export function validateDeploymentSource(sourceCommit, execute = execFileSync) {
  ensure(/^[0-9a-f]{40}$/.test(sourceCommit), 'Pin deployment source commit');
  const git = args => execute('git', args, {cwd: root, encoding: 'utf8', stdio: 'pipe'});
  const current = git(['rev-parse', 'HEAD']).trim();
  if (current !== sourceCommit) {
    try {
      git(['merge-base', '--is-ancestor', sourceCommit, current]);
      const changed = git(['diff', '--name-only', '--no-renames', '-z', sourceCommit, current, '--']).split('\0').filter(Boolean);
      // Keep the original contract/build/registry pin; only coordinator repairs may resume it.
      ensure(changed.every(file => file.startsWith('scripts/deploy-dcap-v2/')), 'Changed deployment inputs');
    } catch {
      throw new Error('Pinned deployment source differs outside scripts/deploy-dcap-v2 or is not an ancestor; do not rewrite checkpoints');
    }
  }
  return current;
}

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
    ensure(['eth_chainId', 'eth_getBlockByNumber', 'eth_getCode', 'eth_call', 'eth_getStorageAt', 'eth_getTransactionReceipt', 'eth_getLogs'].includes(method), 'Read-only RPC required');
    const target = method === 'eth_call'
      ? ` to=${params[0]?.to} selector=${params[0]?.data?.slice(0, 10)} block=${params[1]}`
      : '';
    const label = `RPC ${method}${target}${context ? ` ${context}` : ''}`;
    try {
      const response = await fetchImpl(url, {method: 'POST', headers: {'content-type': 'application/json'},
        body: JSON.stringify({jsonrpc: '2.0', id: ++id, method, params}), signal: AbortSignal.timeout(30000)});
      let body;
      try { body = await response.json(); } catch { throw new Error(`HTTP ${response.status}: invalid JSON response`); }
      if (body?.error) {
        const error = new Error(`HTTP ${response.status}: ${JSON.stringify(body.error)}`);
        const data = body.error.data;
        error.revertData = typeof data === 'string' ? data : data?.data;
        throw error;
      }
      ensure(response.ok, `HTTP ${response.status}`);
      ensure(body && body.result !== undefined, 'Missing JSON-RPC result');
      return body.result;
    } catch (error) {
      const safe = new Error(redact(`${label}: ${error.message}${error.cause?.code ? ` (${error.cause.code})` : ''}`));
      if (/^0x[0-9a-f]*$/i.test(error.revertData ?? '')) safe.revertData = error.revertData;
      throw safe;
    }
  };
}

export function validatePlan(p, {allowPendingVerifier = false} = {}) {
  ensure(p.mode === undefined || ['full', 'replace-entrypoint'].includes(p.mode), 'Unknown deployment mode');
  ensure(p.deploySp1Groth16V6 === undefined || typeof p.deploySp1Groth16V6 === 'boolean', 'SP1 deployment flag must be boolean');
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
    ensure(typeof program.minCheck === 'boolean', 'Explicit program mode required');
    const key = `${program.backend}:${program.minCheck}`;
    ensure([1, 2].includes(program.backend) && !seen.has(key), 'Unsupported/duplicate backend mode');
    seen.add(key);
    if (program.backend === 2) ensure(program.buildSdkVersion === '6.8.0', 'Compact SP1 requires audited SDK 6.8.0 build provenance');
    if (program.backend === 1) {
      ensure(program.buildSdkVersion === '3.1.0', 'RISC Zero requires repaired SDK 3.1.0 build provenance');
      ensure(same(program.proofSelector, '0xe71e6620'), 'RISC Zero requires the repaired 3.1 Groth16 selector');
    }
    ensure(/^0x[0-9a-f]{64}$/i.test(program.id) && !same(program.id, zeroId), 'Invalid native ID');
    ensure(/^0x[0-9a-f]{8}$/i.test(program.proofSelector), 'Invalid proof selector');
    if (program.verifier === pendingSp1Verifier) {
      ensure(allowPendingVerifier && p.deploySp1Groth16V6 === true && program.backend === 2,
        'Unresolved SP1 verifier deployment');
    } else addr(program.verifier);
    if (p.deploySp1Groth16V6 && program.backend === 2) {
      ensure(program.proofSelector === sp1VerifierHash.slice(0, 10), 'Independent SP1 v6 deployment supports v6.1.0 Groth16 only');
    }
    // Provenance references are operator-supplied, not a claim of proof acceptance.
    ensure(/^[0-9a-f]{40}$/.test(program.buildSourceCommit) && /^[0-9a-f]{64}$/.test(program.evidenceSha256)
      && /^[0-9a-f]{64}$/.test(program.artifactSha256), 'Missing matching build provenance');
  }
  for (const program of p.programs) {
    const strict = p.programs.find(item => item.backend === program.backend && !item.minCheck);
    ensure(strict && same(strict.verifier, program.verifier), 'Each backend requires a strict default and consistent verifier');
    ensure(same(strict.proofSelector, program.proofSelector), 'Each backend requires a consistent proof selector');
    ensure(!program.minCheck || !same(strict.id, program.id), 'Strict/minimal IDs must differ');
  }
  if (p.deploySp1Groth16V6) ensure(p.programs.some(p => p.backend === 2), 'SP1 deployment requires SP1 programs');
  if (replacement(p)) {
    ensure(p.sourceRegistryHashes && registryFiles.every(k => /^[0-9a-f]{64}$/.test(p.sourceRegistryHashes[k])), 'Pin source V2 registry');
    ensure(/^0x[0-9a-f]{64}$/i.test(p.sourceDeploymentTx), 'Pin source deployment transaction');
    ensure(p.reusedContracts && Object.keys(p.reusedContracts).sort().join() === contractKeys.filter(k => k !== 'AutomataDcapAttestationV2').sort().join(),
      'Exactly five reused contracts required');
    Object.values(p.reusedContracts).forEach(addr);
    ensure(same(p.reusedContracts.PCCSRouterV2, p.legacyRouter), 'Replacement Router mismatch');
    const directory = path.join(root, 'rust-crates/libraries/network-registry/deployment/v2.0', String(p.chainId));
    ensure(JSON.stringify(registryHashes(directory)) === JSON.stringify(p.sourceRegistryHashes), 'Source registry changed');
    validateReplacement(p, json(path.join(directory, 'manifest.json')));
  }
}

export function makeDocuments(p, legacyDcap, legacyPccs) {
  const contracts = p.contracts;
  ensure(contracts && JSON.stringify(Object.keys(contracts).sort()) === JSON.stringify([...contractKeys].sort()), 'Exactly six V2 contract keys required');
  contractKeys.forEach(k => addr(contracts[k]));
  ensure(new Set(contractKeys.map(k => contracts[k].toLowerCase())).size === 6, 'Six distinct contracts required');
  if (replacement(p)) {
    ensure(same(legacyDcap.AutomataDcapAttestationV2, p.legacyFee), 'Source V2 entrypoint registry mismatch');
    for (const [key, address] of Object.entries(p.reusedContracts)) ensure(same(contracts[key], address), 'Reused component changed');
    ensure(!Object.values(legacyDcap).some(a => same(a, contracts.AutomataDcapAttestationV2)), 'Replacement aliases existing deployment');
    return {dcap: {...legacyDcap, ...contracts}, pccs: {...legacyPccs, PCKHelperV2: contracts.PCKHelperV2}};
  }
  ensure(same(legacyDcap.AutomataDcapAttestationFee, p.legacyFee)
    && same(legacyDcap.PCCSRouter, p.legacyRouter), 'Legacy registry does not match plan');
  const oldAddresses = new Set([...Object.values(legacyDcap), ...Object.values(legacyPccs)]
    .filter(v => typeof v === 'string').map(v => v.toLowerCase()));
  contractKeys.forEach(k => ensure(!oldAddresses.has(contracts[k].toLowerCase()), 'New address aliases existing deployment'));
  // Preserve legacy keys: consumers must explicitly select V2 keys, including the Router.
  const dcap = {...legacyDcap, ...contracts};
  if (p.deploySp1Groth16V6) {
    addr(p.sp1Groth16Verifier);
    ensure(!oldAddresses.has(p.sp1Groth16Verifier.toLowerCase()), 'New SP1 verifier aliases legacy deployment');
    ensure(!Object.values(contracts).some(a => same(a, p.sp1Groth16Verifier)), 'SP1 verifier aliases V2 deployment');
    dcap.SP1Groth16VerifierV6 = p.sp1Groth16Verifier;
  }
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
    const suffix = replacement(p) ? 'V2' : '';
    const verifier = await call(p.legacyFee, `zkVerifier${suffix}(uint8)`, 'address', backend);
    backends[backend] = {verifier, code: same(verifier, zero) ? '0x' : await code(verifier),
      defaultId: await call(p.legacyFee, `programIdentifier${suffix}(uint8)`, 'bytes32', backend),
      ids: await call(p.legacyFee, `programIdentifiers${suffix}(uint8)`, 'bytes32[]', backend)};
  }
  for (const program of p.programs) {
    // The explicitly reviewed V2 inventory is independent of disabled/absent legacy backends.
    if (program.verifier !== pendingSp1Verifier) ensure(await code(program.verifier) !== '0x', 'Selected backend verifier has no code');
    // SP1 v6 may require a different reviewed verifier from the legacy v5 route.
    if (!replacement(p) || program.backend !== 2) ensure(!backends[program.backend].ids.some(id => same(id, program.id)), 'Legacy ID cannot be registered as compact V2');
  }
  const result = {router, evaluations, backends, verifiers,
    feeOwner: await call(p.legacyFee, 'owner()', 'address'),
    routerOwner: await call(p.legacyRouter, 'owner()', 'address'),
    feeBp: String(await call(p.legacyFee, 'getBp()', 'uint16')),
    feeCode: await code(p.legacyFee), routerCode: await code(p.legacyRouter)};
  if (replacement(p)) result.migration = await readReplacementState(p, result, rpc);
  return result;
}

export async function verifyNew(p, legacy, documents, rpc) {
  if (replacement(p)) return verifyReplacement(p, legacy, rpc);
  const {call, code, storage} = rpc;
  const c = p.contracts, router = c.PCCSRouterV2, attestation = c.AutomataDcapAttestationV2;
  const codeHashes = {}, resolvers = new Set();
  if (p.deploySp1Groth16V6) {
    addr(p.sp1Groth16Verifier);
    ensure(await code(p.sp1Groth16Verifier) !== '0x', 'SP1 v6 verifier has no code');
    ensure(await call(p.sp1Groth16Verifier, 'VERSION()', 'string') === 'v6.1.0', 'Wrong SP1 circuit');
    ensure(same(await call(p.sp1Groth16Verifier, 'VERIFIER_HASH()', 'bytes32'), sp1VerifierHash), 'Wrong SP1 verifier hash');
    ensure(p.programs.filter(p => p.backend === 2).every(x => same(x.verifier, p.sp1Groth16Verifier)), 'SP1 program/verifier mismatch');
    const runtime = await code(p.sp1Groth16Verifier);
    await rpc.verifyArtifact('SP1Groth16VerifierV6', runtime);
    codeHashes.SP1Groth16VerifierV6 = sha(Buffer.from(runtime.slice(2), 'hex'));
  }
  for (const key of contractKeys) {
    const runtime = await code(c[key]); ensure(runtime !== '0x', `${key} has no code`);
    await rpc.verifyArtifact(key, runtime);
    codeHashes[key] = sha(Buffer.from(runtime.slice(2), 'hex'));
  }
  for (const target of [router, attestation]) ensure(same(await call(target, 'owner()', 'address'), p.owner), 'New owner mismatch');
  ensure(String(await call(attestation, 'getBp()', 'uint16')) === legacy.feeBp, 'Fee basis points mismatch');
  ensure(await call(attestation, 'zkV2Paused()', 'bool') === (p.programs.length === 0), 'Unexpected ZK pause state');
  for (const name of componentNames) {
    ensure(same(await call(router, `${name}()`, 'address'),
      name === 'pckHelperAddr' ? c.PCKHelperV2 : legacy.router[name]), 'Router dependency mismatch');
  }
  // The adapter checks the exact local Router runtime before relying on its storage layout.
  await rpc.verifyRouterLayout(router);
  const packed = BigInt(await storage(router, '0x1'));
  ensure((packed & 255n) === 1n && ((packed >> 8n) & ((1n << 160n) - 1n))
    === BigInt(legacy.router.tcbEvalDaoAddr), 'Router restriction/layout mismatch');
  for (const target of [attestation, c.V3QuoteVerifierV2, c.V4QuoteVerifierV2, c.V5QuoteVerifierV2]) {
    ensure(await rpc.authorized(router, target), 'Missing Router reader authorization');
  }
  for (const version of [3, 4, 5]) {
    const verifier = c[`V${version}QuoteVerifierV2`];
    ensure(same(await call(attestation, 'quoteVerifiers(uint16)', 'address', version), verifier), 'Fee verifier mismatch');
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
    const programs = p.programs.filter(item => item.backend === backend);
    const program = programs.find(item => !item.minCheck);
    const ids = await call(attestation, 'programIdentifiersV2(uint8)', 'bytes32[]', backend);
    ensure(ids.length === programs.length, 'Unexpected V2 ID inventory');
    ensure(same(await call(attestation, 'programIdentifierV2(uint8)', 'bytes32', backend), program?.id ?? zeroId), 'V2 default ID mismatch');
    if (program) {
      for (const entry of programs) {
        ensure(ids.some(id => same(id, entry.id)), 'V2 ID mismatch');
        const [registered, minCheck] = await call(attestation, 'programModeV2(uint8,bytes32)', 'bool,bool', backend, entry.id);
        ensure(registered && minCheck === entry.minCheck, 'V2 program mode mismatch');
        for (const selector of ['0x00000000', entry.proofSelector]) {
          const expected = backend === 1 && selector === '0x00000000' ? zero : entry.verifier;
          ensure(same(await call(attestation, 'zkVerifierV2(uint8,bytes4)', 'address', backend, selector), expected), 'V2 proof route mismatch');
        }
      }
    }
  }
  return {runtimeSha256: codeHashes, readerStorages: [...resolvers]};
}

export function createReadbackRpc(request, block, execute = execFileSync) {
  const cast = (...args) => execute('cast', args, {encoding: 'utf8', maxBuffer: 8 * 1024 * 1024}).trim();
  const rpc = {
    call: async (to, sig, returns, ...args) => { const decoded = JSON.parse(cast('abi-decode', '--json', `f()(${returns})`,
      await request('eth_call', [{to, data: cast('calldata', sig, ...args.map(String))}, block.number],
        `function=${sig} args=${JSON.stringify(args)}`))); return returns.includes(',') ? decoded : decoded[0]; },
    code: to => request('eth_getCode', [to, block.number]),
    storage: (to, slot) => request('eth_getStorageAt', [to, slot, block.number]),
    verifyArtifact: async (key, runtime) => {
      const name = key === 'AutomataDcapAttestationV2' ? key : key.replace(/V2$/, '');
      const artifact = readBuildArtifact(name);
      const actual = Buffer.from(runtime.slice(2), 'hex');
      const expected = Buffer.from(artifact.deployedBytecode.object.replace(/^0x/, ''), 'hex');
      ensure(actual.length > 0 && actual.length <= 24576 && actual.length === expected.length, 'Invalid deployed runtime size');
      for (const refs of Object.values(artifact.deployedBytecode.immutableReferences ?? {})) {
        ensure(new Set(refs.map(r => actual.subarray(r.start, r.start + r.length).toString('hex'))).size === 1, 'Inconsistent immutables');
        for (const r of refs) { actual.fill(0, r.start, r.start + r.length); expected.fill(0, r.start, r.start + r.length); }
      }
      ensure(actual.equals(expected), `${key} runtime differs from local artifact`);
    },
    verifyRouterLayout: async (to, allowMetadataDifference = false) => {
      const artifact = readBuildArtifact('PCCSRouter');
      const expected = artifact.deployedBytecode.object;
      const actual = await rpc.code(to);
      ensure(allowMetadataDifference ? executableRuntime(actual).equals(executableRuntime(expected))
        : same(actual, expected.startsWith('0x') ? expected : '0x' + expected), 'Router runtime differs from local reviewed artifact');
    },
    authorized: async (router, reader) => BigInt(await rpc.storage(router,
      cast('keccak', cast('abi-encode', 'f(address,uint256)', reader, '0')))) === 1n,
    receipt: async hash => {
      const receipt = await request('eth_getTransactionReceipt', [hash]);
      ensure(receipt && BigInt(receipt.blockNumber) <= BigInt(block.number), 'Source receipt is not finalized');
      ensure((await request('eth_getBlockByNumber', [receipt.blockNumber, false]))?.hash === receipt.blockHash,
        'Source deployment block changed');
      return receipt;
    },
    route: async (to, backend, selector) => {
      try { return await rpc.call(to, 'zkVerifierV2(uint8,bytes4)', 'address', backend, selector); }
      catch (error) {
        const expected = cast('calldata', 'ZK_Route_Frozen(uint8,bytes4)', String(backend), selector);
        if (same(error.revertData, expected)) return frozenRoute;
        throw error; // Never interpret a provider outage or unrelated revert as a frozen route.
      }
    },
    routeEvents: async (to, fromBlock) => {
      const added = cast('keccak', 'ZkRouteAdded(uint8,bytes4,address)');
      const frozen = cast('keccak', 'ZkRouteFrozen(uint8,bytes4)');
      const events = [];
      let width = 10000n;
      for (let start = BigInt(fromBlock); start <= BigInt(block.number);) {
        const end = start + width - 1n < BigInt(block.number) ? start + width - 1n : BigInt(block.number);
        let logs;
        try {
          logs = await request('eth_getLogs', [{address: to, fromBlock: '0x' + start.toString(16),
            toBlock: '0x' + end.toString(16), topics: [[added, frozen]]}]);
        } catch (error) {
          if (width > 1n && /range|too many results|response size/i.test(error.message)) { width /= 2n; continue; }
          throw error;
        }
        logs.sort((a, b) => Number(BigInt(a.blockNumber) - BigInt(b.blockNumber)) || Number(BigInt(a.logIndex) - BigInt(b.logIndex)));
        for (const log of logs) {
          ensure(same(log.address, to) && log.topics.length === 2 && [added, frozen].some(t => same(t, log.topics[0]))
            && /^0x[0-9a-f]+$/i.test(log.data) && log.data.length === (same(log.topics[0], frozen) ? 66 : 130), 'Invalid route event');
          // Only backend is indexed; bytes4 selector is the first ABI word in event data.
          events.push({backend: Number(BigInt(log.topics[1])), selector: log.data.slice(0, 10),
            frozen: same(log.topics[0], frozen), verifier: same(log.topics[0], frozen) ? frozenRoute : '0x' + log.data.slice(-40),
            removed: log.removed});
        }
        start = end + 1n;
      }
      return events;
    },
  };
  return rpc;
}

async function main() {
  const [mode, planFile, snapshotFile, reportFile] = process.argv.slice(2);
  ensure(['snapshot', 'check', 'publish'].includes(mode) && planFile && snapshotFile
    && (mode !== 'publish' || reportFile), 'Usage: publish-v2.mjs snapshot|check PLAN SNAPSHOT | publish PLAN SNAPSHOT NEW_REPORT');
  const p = json(planFile); validatePlan(p, {allowPendingVerifier: mode !== 'publish'});
  const coordinatorCommit = validateDeploymentSource(p.sourceCommit);
  validateBuildSources(p);
  const url = process.env.DCAP_RPC_URL; ensure(url, 'DCAP_RPC_URL required');
  const request = createRpcRequest(url);
  ensure(Number(BigInt(await request('eth_chainId'))) === p.chainId, 'Wrong RPC chain');
  const block = await request('eth_getBlockByNumber', ['finalized', false]);
  ensure(block?.hash && block?.number, 'RPC must provide finalized block');
  const rpc = createReadbackRpc(request, block);
  const legacy = await readLegacy(p, rpc);
  const identity = {chainId: p.chainId, legacyFee: p.legacyFee, legacyRouter: p.legacyRouter,
    evaluations: p.evaluations, sourceCommit: p.sourceCommit, mode: p.mode,
    sourceRegistryHashes: p.sourceRegistryHashes};
  if (mode === 'snapshot') {
    fs.writeFileSync(snapshotFile, encoded({identity, block, legacy}), {flag: 'wx'});
    console.log('Read-only legacy snapshot saved. No deployment or registry writes.'); return;
  }
  const before = json(snapshotFile);
  ensure(JSON.stringify(before.identity) === JSON.stringify(identity), 'Snapshot/plan mismatch');
  ensure(BigInt(before.block.number) <= BigInt(block.number), 'Snapshot is newer than finalized readback');
  ensure((await request('eth_getBlockByNumber', [before.block.number, false]))?.hash === before.block.hash, 'Snapshot block changed');
  ensure(JSON.stringify(legacy) === JSON.stringify(before.legacy), 'Legacy configuration changed since snapshot');
  if (mode === 'check') { console.log('Source configuration unchanged.'); return; }
  ensure(Array.isArray(p.transactions) && p.transactions.length >= (replacement(p) ? 1 : p.deploySp1Groth16V6 ? 7 : 6), 'Deployment transaction inventory required');
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
  const source = path.join(registry, replacement(p) ? 'v2.0' : 'current', String(p.chainId));
  const documents = makeDocuments(p, json(path.join(source, 'dcap.json')), json(path.join(source, 'onchain_pccs.json')));
  for (const key of replacement(p) ? ['AutomataDcapAttestationV2'] : contractKeys) ensure(receipts.some(r => same(r.contractAddress, p.contracts[key])), 'Missing direct deployment receipt for ' + key);
  if (replacement(p)) ensure(receipts.filter(r => r.contractAddress).length === 1, 'Replacement must deploy exactly one contract');
  if (p.deploySp1Groth16V6) ensure(receipts.some(r => same(r.contractAddress, p.sp1Groth16Verifier)), 'Missing SP1 v6 deployment receipt');
  const verified = await verifyNew(p, legacy, documents, rpc);
  const pccsPath = path.join(root, 'evm/lib/automata-on-chain-pccs/deployment', `${p.chainId}.json`);
  const originalPccs = fs.readFileSync(pccsPath, 'utf8');
  const pccsUpdate = replacement(p) ? JSON.parse(originalPccs) : updatePccsDeployment(JSON.parse(originalPccs), p.contracts.PCKHelperV2);
  const destination = requirePublication(p, reportFile);
  ensure((await request('eth_getBlockByNumber', [block.number, false]))?.hash === block.hash, 'Readback block changed');
  const report = {status: 'TEST_DEPLOYMENT_READBACK_PASS_NOT_PROOF_OR_RELEASE_ACCEPTANCE', coordinatorCommit,
    plan: p, block, transactions: receipts, legacySnapshotSha256: sha(fs.readFileSync(snapshotFile)), ...verified,
    ...(replacement(p) ? {migratedSp1: legacy.migration.sp1} : {}),
    pccsDeploymentBefore: JSON.parse(originalPccs), currentPromoted: false};
  // Stage complete files before publishing the new directory; current/v1.1 are never written.
  const parent = path.dirname(destination);
  fs.mkdirSync(parent, {recursive: true});
  const stage = fs.mkdtempSync(path.join(parent, '.staging-'));
  fs.writeFileSync(path.join(stage, 'dcap.json'), encoded(documents.dcap));
  fs.writeFileSync(path.join(stage, 'onchain_pccs.json'), encoded(documents.pccs));
  fs.writeFileSync(path.join(stage, 'manifest.json'), encoded(report));
  ensure(fs.readFileSync(pccsPath, 'utf8') === originalPccs, 'PCCS registry changed concurrently');
  // A readback file plus an incomplete move is intentionally not treated as success on resume.
  fs.writeFileSync(reportFile, encoded(report), {flag: 'wx'});
  if (replacement(p)) {
    const archive = path.join(registry, 'history', String(p.chainId), p.legacyFee.toLowerCase());
    fs.mkdirSync(path.dirname(archive), {recursive: true});
    ensure(!fs.existsSync(archive), 'Historical deployment already archived; inspect publication state');
    fs.renameSync(destination, archive);
  }
  fs.renameSync(stage, destination);
  // Additive key only. Existing PCKHelper and every other PCCS key are preserved.
  if (!replacement(p)) fs.writeFileSync(pccsPath, encoded(pccsUpdate));
  console.log(`Published TEST_ONLY ${destination}; ${replacement(p) ? 'previous V2 archived; PCCS deployment unchanged' : 'PCKHelperV2 recorded'}. current and ZK submodules unchanged.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
