import test from 'node:test';
import assert from 'node:assert/strict';
import {validatePlan, makeDocuments, updatePccsDeployment, readLegacy, verifyNew, createRpcRequest, pendingSp1Verifier} from './publish-v2.mjs';

const a = n => '0x' + n.toString(16).padStart(40, '0');
const id = n => '0x' + n.toString(16).padStart(64, '0');
function fixture() {
  const p = {chainId: 560048, status: 'TEST_ONLY', sourceCommit: 'a'.repeat(40),
    owner: a(1), legacyFee: a(2), legacyRouter: a(3), p256: a(256), evaluations: [21], programs: [],
    contracts: {AutomataDcapAttestationV2: a(10), PCCSRouterV2: a(11), PCKHelperV2: a(12),
      V3QuoteVerifierV2: a(13), V4QuoteVerifierV2: a(14), V5QuoteVerifierV2: a(15)}};
  const dcap = {AutomataDcapAttestationFee: a(2), PCCSRouter: a(3), V3QuoteVerifier: a(4)};
  const pccs = {AutomataTcbEvalDao: a(21), AutomataPcsDao: a(22), AutomataPckDao: a(23), PCKHelper: a(24),
    AutomataEnclaveIdentityDaoVersioned_tcbeval_21: a(30), AutomataFmspcTcbDaoVersioned_tcbeval_21: a(31),
    AutomataEnclaveIdentityDaoVersioned_tcbeval_20: a(32)};
  const legacy = {feeBp: '123', router: {tcbEvalDaoAddr: a(21), pcsDaoAddr: a(22), pckDaoAddr: a(23),
    pckHelperAddr: a(24), crlHelperAddr: a(25), fmspcTcbHelperAddr: a(26)},
    evaluations: {21: {qeIdDaoVersionedAddr: a(30), fmspcTcbDaoVersionedAddr: a(31)}}};
  const values = new Map();
  const key = (to, sig, args) => [to, sig, ...args].join('|');
  const set = (to, sig, value, ...args) => values.set(key(to, sig, args), value);
  const c = p.contracts;
  for (const to of [c.AutomataDcapAttestationV2, c.PCCSRouterV2]) set(to, 'owner()', p.owner);
  set(c.AutomataDcapAttestationV2, 'getBp()', '123');
  set(c.AutomataDcapAttestationV2, 'zkV2Paused()', true);
  for (const [name, value] of Object.entries(legacy.router)) set(c.PCCSRouterV2, name + '()', name === 'pckHelperAddr' ? c.PCKHelperV2 : value);
  for (const version of [3, 4, 5]) {
    const v = c[`V${version}QuoteVerifierV2`];
    set(c.AutomataDcapAttestationV2, 'quoteVerifiers(uint16)', v, version);
    set(v, 'quoteVersion()', String(version)); set(v, 'pccsRouter()', c.PCCSRouterV2); set(v, 'P256_VERIFIER()', p.p256);
  }
  for (const [name, value] of Object.entries(legacy.evaluations[21])) set(c.PCCSRouterV2, `${name}(uint32)`, value, 21);
  for (const dao of [a(21), a(22), a(23), a(30), a(31)]) set(dao, 'resolver()', a(40));
  set(a(40), 'isAuthorizedCaller(address)', true, c.PCCSRouterV2);
  for (const backend of [1, 2, 3]) {
    set(c.AutomataDcapAttestationV2, 'programIdentifiersV2(uint8)', [], backend);
    set(c.AutomataDcapAttestationV2, 'programIdentifierV2(uint8)', id(0), backend);
  }
  const rpc = {call: async (to, sig, ret, ...args) => {
    assert.ok(values.has(key(to, sig, args)), `Unexpected call ${key(to, sig, args)}`);
    return values.get(key(to, sig, args));
  }, code: async () => '0x6000', storage: async () => '0x' + ((BigInt(a(21)) << 8n) | 1n).toString(16),
  verifyArtifact: async () => {}, verifyRouterLayout: async () => {}, authorized: async () => true};
  return {p, dcap, pccs, legacy, rpc, set};
}

test('V2 documents preserve legacy keys and additive PCCS helper without mutating input', () => {
  const {p, dcap, pccs} = fixture(); const original = structuredClone({dcap, pccs});
  validatePlan(p);
  const docs = makeDocuments(p, dcap, pccs);
  assert.equal(docs.dcap.PCCSRouter, p.legacyRouter);
  assert.equal(docs.dcap.PCCSRouterV2, p.contracts.PCCSRouterV2);
  assert.equal(docs.pccs.PCKHelper, pccs.PCKHelper);
  assert.equal(docs.pccs.PCKHelperV2, p.contracts.PCKHelperV2);
  assert.equal(docs.pccs.AutomataEnclaveIdentityDaoVersioned_tcbeval_20, undefined);
  assert.deepEqual({dcap, pccs}, original);
  const updated = updatePccsDeployment(pccs, p.contracts.PCKHelperV2);
  delete updated.PCKHelperV2;
  assert.deepEqual(updated, pccs);
});
test('reject missing/aliased contracts, extra legacy overwrite keys and stale registry', () => {
  for (const mutation of [
    p => { delete p.contracts.PCCSRouterV2; },
    p => { p.contracts.PCCSRouterV2 = p.legacyRouter; },
    p => { p.contracts.PCKHelperV2 = p.contracts.PCCSRouterV2; },
    p => { p.contracts.PCCSRouter = a(70); },
    p => { p.legacyFee = a(70); },
  ]) {
    const {p, dcap, pccs} = fixture(); mutation(p);
    assert.throws(() => makeDocuments(p, dcap, pccs));
  }
});
test('reject Pico, duplicate/unsorted evaluations and missing build provenance', () => {
  for (const mutation of [
    p => { p.evaluations = [21, 20]; }, p => { p.evaluations = []; },
    p => { p.evaluations = [21, 21]; }, p => { p.programs = [{backend: 3}]; },
    p => { p.programs = [{backend: 2, id: id(99), proofSelector: '0x12345678', verifier: a(99)}]; },
  ]) {
    const {p} = fixture(); mutation(p); assert.throws(() => validatePlan(p));
  }
});
test('raw-only readback requires paused ZK and all reader authorizations', async () => {
  const {p, legacy, rpc, dcap, pccs} = fixture();
  const result = await verifyNew(p, legacy, makeDocuments(p, dcap, pccs), rpc);
  assert.deepEqual(result.readerStorages, [a(40)]);
  assert.equal(Object.keys(result.runtimeSha256).length, 6);
  await assert.rejects(verifyNew(p, legacy, makeDocuments(p, dcap, pccs), {...rpc, authorized: async () => false}), /authorization/);
});
test('readback fails on wrong Router, missing Storage permission, stale DAO or unexpected Pico', async () => {
  for (const mutation of [
    f => f.set(a(13), 'pccsRouter()', a(3)),
    f => f.set(a(40), 'isAuthorizedCaller(address)', false, a(11)),
    f => { f.pccs.AutomataPcsDaoV2 = a(80); },
    f => f.set(a(10), 'programIdentifiersV2(uint8)', [id(99)], 3),
    f => f.set(a(10), 'zkV2Paused()', false),
  ]) {
    const f = fixture(); mutation(f);
    await assert.rejects(verifyNew(f.p, f.legacy, makeDocuments(f.p, f.dcap, f.pccs), f.rpc));
  }
});
test('configured ZK requires enabled state, exact program ID and matching proof route', async () => {
  const f = fixture();
  f.p.programs = [{backend: 2, buildSdkVersion: '6.8.0', minCheck: false, id: id(99), proofSelector: '0x12345678', verifier: a(99),
    buildSourceCommit: f.p.sourceCommit, evidenceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64)}];
  validatePlan(f.p);
  f.set(a(10), 'zkV2Paused()', false);
  f.set(a(10), 'programIdentifiersV2(uint8)', [id(99)], 2);
  f.set(a(10), 'programIdentifierV2(uint8)', id(99), 2);
  f.set(a(10), 'programModeV2(uint8,bytes32)', [true, false], 2, id(99));
  f.set(a(10), 'zkVerifierV2(uint8,bytes4)', a(99), 2, '0x00000000');
  f.set(a(10), 'zkVerifierV2(uint8,bytes4)', a(99), 2, '0x12345678');
  const docs = makeDocuments(f.p, f.dcap, f.pccs);
  await verifyNew(f.p, f.legacy, docs, f.rpc);
  f.set(a(10), 'programIdentifierV2(uint8)', id(100), 2);
  await assert.rejects(verifyNew(f.p, f.legacy, docs, f.rpc), /ID mismatch/);
});
test('legacy snapshot reads only; a missing legacy backend fails scope check', async () => {
  const f = fixture();
  const reads = [];
  const fake = {code: async () => '0x6000', call: async (to, sig, ret, ...args) => {
    if (['zkVerifier(uint8)', 'programIdentifier(uint8)', 'programIdentifiers(uint8)'].includes(sig)) {
      reads.push([sig, args[0]]);
      if (args[0] === 3) throw new Error('legacy ABI rejects Pico enum');
    }
    if (sig === 'TCB_EVALUATION_NUMBER()') return 21;
    if (sig === 'pccsRouter()') return f.p.legacyRouter;
    if (sig.startsWith('programIdentifiers')) return [];
    if (sig.startsWith('programIdentifier')) return id(0);
    if (sig.startsWith('zkVerifier')) return a(0);
    if (sig === 'getBp()') return '123';
    return a(30);
  }};
  const snapshot = await readLegacy(f.p, fake);
  assert.equal(snapshot.backends[2].verifier, a(0));
  assert.deepEqual(Object.keys(snapshot.backends), ['1', '2']);
  assert.deepEqual(reads, [1, 2].flatMap(backend =>
    ['zkVerifier(uint8)', 'programIdentifier(uint8)', 'programIdentifiers(uint8)'].map(sig => [sig, backend])));
  await assert.rejects(readLegacy(f.p, {...fake, call: async (...args) => {
    if (args[1] === 'zkVerifier(uint8)' && args[3] === 1) throw new Error('RISC Zero RPC failure');
    return fake.call(...args);
  }}), /RISC Zero RPC failure/);
  f.p.programs = [{backend: 2, verifier: a(99)}];
  await assert.rejects(readLegacy(f.p, fake), /expansion/);
});

test('strict and minimal IDs have exact modes and only strict can be the default', async () => {
  const f = fixture();
  const strict = {backend: 2, buildSdkVersion: '6.8.0', minCheck: false, id: id(99), proofSelector: '0x12345678', verifier: a(99),
    buildSourceCommit: f.p.sourceCommit, evidenceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64)};
  const minimal = {...strict, minCheck: true, id: id(100)};
  f.p.programs = [minimal, strict];
  validatePlan(f.p);
  f.set(a(10), 'zkV2Paused()', false);
  f.set(a(10), 'programIdentifiersV2(uint8)', [id(100), id(99)], 2);
  f.set(a(10), 'programIdentifierV2(uint8)', id(99), 2);
  f.set(a(10), 'programModeV2(uint8,bytes32)', [true, false], 2, id(99));
  f.set(a(10), 'programModeV2(uint8,bytes32)', [true, true], 2, id(100));
  for (const selector of ['0x00000000', '0x12345678']) f.set(a(10), 'zkVerifierV2(uint8,bytes4)', a(99), 2, selector);
  const docs = makeDocuments(f.p, f.dcap, f.pccs);
  await verifyNew(f.p, f.legacy, docs, f.rpc);
  f.set(a(10), 'programModeV2(uint8,bytes32)', [true, false], 2, id(100));
  await assert.rejects(verifyNew(f.p, f.legacy, docs, f.rpc), /mode mismatch/);
  for (const programs of [[minimal], [strict, {...minimal, id: strict.id}], [strict, {...strict}], [{...strict, minCheck: undefined}], [{...strict, buildSdkVersion: '5.2.2'}]]) {
    assert.throws(() => validatePlan({...f.p, programs}));
  }
});

test('new Fee readback still queries Pico and rejects a Pico default ID', async () => {
  const f = fixture();
  const reads = [];
  const rpc = {...f.rpc, call: async (...args) => {
    if (args[0] === f.p.contracts.AutomataDcapAttestationV2 && args[3] === 3
      && args[1].startsWith('programIdentifier')) reads.push(args[1]);
    return f.rpc.call(...args);
  }};
  await verifyNew(f.p, f.legacy, makeDocuments(f.p, f.dcap, f.pccs), rpc);
  assert.deepEqual(reads, ['programIdentifiersV2(uint8)', 'programIdentifierV2(uint8)']);
  f.set(f.p.contracts.AutomataDcapAttestationV2, 'programIdentifierV2(uint8)', id(99), 3);
  await assert.rejects(verifyNew(f.p, f.legacy, makeDocuments(f.p, f.dcap, f.pccs), rpc), /default ID mismatch/);
});

test('new SP1 placeholder is snapshot-only and requires the v6.1 Groth16 selector', () => {
  const {p} = fixture();
  p.deploySp1Groth16V6 = true;
  p.programs = [{backend: 2, buildSdkVersion: '6.8.0', minCheck: false, id: id(99),
    verifier: pendingSp1Verifier, proofSelector: '0x4388a21c', buildSourceCommit: p.sourceCommit,
    artifactSha256: 'a'.repeat(64), evidenceSha256: 'b'.repeat(64)}];
  validatePlan(p, {allowPendingVerifier: true});
  assert.throws(() => validatePlan(p), /Unresolved/);
  p.programs[0].proofSelector = '0x12345678';
  assert.throws(() => validatePlan(p, {allowPendingVerifier: true}), /Groth16 only/);
  p.programs = [];
  assert.throws(() => validatePlan(p), /requires SP1 programs/);
});

test('independent SP1 verifier is recorded and checked against version, hash, runtime and program route', async () => {
  const f = fixture();
  f.p.deploySp1Groth16V6 = true;
  f.p.sp1Groth16Verifier = a(99);
  f.p.programs = [{backend: 2, buildSdkVersion: '6.8.0', minCheck: false, id: id(99),
    verifier: a(99), proofSelector: '0x4388a21c', buildSourceCommit: f.p.sourceCommit,
    artifactSha256: 'a'.repeat(64), evidenceSha256: 'b'.repeat(64)}];
  validatePlan(f.p);
  f.set(a(99), 'VERSION()', 'v6.1.0');
  f.set(a(99), 'VERIFIER_HASH()', '0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696');
  f.set(a(10), 'zkV2Paused()', false);
  f.set(a(10), 'programIdentifiersV2(uint8)', [id(99)], 2);
  f.set(a(10), 'programIdentifierV2(uint8)', id(99), 2);
  f.set(a(10), 'programModeV2(uint8,bytes32)', [true, false], 2, id(99));
  for (const selector of ['0x00000000', '0x4388a21c']) f.set(a(10), 'zkVerifierV2(uint8,bytes4)', a(99), 2, selector);
  const docs = makeDocuments(f.p, f.dcap, f.pccs);
  assert.equal(docs.dcap.SP1Groth16VerifierV6, a(99));
  assert.equal(f.dcap.SP1Groth16VerifierV6, undefined);
  const checked = [];
  const rpc = {...f.rpc, verifyArtifact: async key => { checked.push(key); }};
  const result = await verifyNew(f.p, f.legacy, docs, rpc);
  assert.equal(Object.keys(result.runtimeSha256).length, 7);
  assert.ok(checked.includes('SP1Groth16VerifierV6'));
  f.set(a(99), 'VERSION()', 'v5.0.0');
  await assert.rejects(verifyNew(f.p, f.legacy, docs, rpc), /Wrong SP1 circuit/);
  f.set(a(99), 'VERSION()', 'v6.1.0');
  f.set(a(99), 'VERIFIER_HASH()', id(0));
  await assert.rejects(verifyNew(f.p, f.legacy, docs, rpc), /Wrong SP1 verifier hash/);
  f.p.sp1Groth16Verifier = f.p.legacyFee;
  assert.throws(() => makeDocuments(f.p, f.dcap, f.pccs), /aliases legacy/);
});

test('RPC preserves pinned request and falsy result; blocks writes before fetch', async () => {
  const calls = [];
  const request = createRpcRequest('https://rpc.example/v2/key', async (url, options) => {
    calls.push(JSON.parse(options.body));
    return {ok:true, status:200, json:async () => ({result:false})};
  });
  assert.equal(await request('eth_call', [{to:a(2), data:'0x12345678'}, '0x3792a4']), false);
  assert.deepEqual(calls[0], {jsonrpc:'2.0', id:1, method:'eth_call', params:[{to:a(2), data:'0x12345678'}, '0x3792a4']});
  await assert.rejects(request('eth_sendRawTransaction', ['0x00']), /Read-only/);
  assert.equal(calls.length, 1);
});

test('RPC revert includes target/function/args/block/code/data and redacts credentials', async () => {
  const url = 'https://rpcuser:rpcpassword@rpc.example/v2/alchemy-secret-key?apiKey=query-secret-key';
  const request = createRpcRequest(url, async () => ({ok:true, status:200, json:async () => ({
    error:{code:3, message:`execution reverted via ${url}; alchemy-secret-key query-secret-key rpcpassword`, data:'0xdeadbeef'}
  })}));
  await assert.rejects(request('eth_call', [{to:a(2), data:'0x12345678'}, '0x3792a4'],
    'function=zkVerifier(uint8) args=[3]'), error => {
    for (const part of [a(2), 'zkVerifier(uint8)', 'args=[3]', '0x3792a4', '"code":3', 'execution reverted', '0xdeadbeef']) {
      assert.ok(error.message.includes(part), part);
    }
    for (const secret of [url, 'rpcuser', 'rpcpassword', 'alchemy-secret-key', 'query-secret-key']) {
      assert.ok(!error.message.includes(secret), secret);
    }
    return true;
  });
});

test('HTTP rate-limit errors retain provider details without leaking endpoint', async () => {
  const url = 'https://rpc.example/v2/private-api-key';
  const request = createRpcRequest(url, async () => ({ok:false, status:429,
    json:async () => ({error:{code:429, message:`rate limited: ${url}`}})}));
  await assert.rejects(request('eth_chainId'), error => {
    assert.match(error.message, /HTTP 429.*rate limited/);
    assert.ok(!error.message.includes('private-api-key')); return true;
  });
});

test('network errors retain cause code without leaking URL credentials', async () => {
  const url = 'https://rpc.example/v2/private-api-key';
  const request = createRpcRequest(url, async () => {
    throw new TypeError(`fetch failed ${url}`, {cause:{code:'ECONNRESET'}});
  });
  await assert.rejects(request('eth_chainId'), error => {
    assert.match(error.message, /fetch failed.*ECONNRESET/);
    assert.ok(!error.message.includes('private-api-key')); return true;
  });
});

test('invalid JSON and missing result fail closed', async () => {
  for (const response of [
    {ok:false, status:502, json:async () => { throw new Error('raw HTML with credentials'); }},
    {ok:true, status:200, json:async () => ({jsonrpc:'2.0', id:1})},
  ]) {
    const request = createRpcRequest('https://rpc.example', async () => response);
    await assert.rejects(request('eth_chainId'), /invalid JSON response|Missing JSON-RPC result/);
  }
});
