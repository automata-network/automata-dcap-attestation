// Entrypoint-only migration: source state is read, never repaired or silently discarded.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';

const ensure = (ok, message) => { if (!ok) throw new Error(message); };
const same = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();
export const frozenRoute = '0x000000000000000000000000000000000000dead';
export const replacement = p => p.mode === 'replace-entrypoint';
export const digest = bytes => createHash('sha256').update(bytes).digest('hex');
export const registryFiles = ['dcap.json', 'onchain_pccs.json', 'manifest.json'];
export function registryHashes(directory) {
  return Object.fromEntries(registryFiles.map(name => [name, digest(fs.readFileSync(path.join(directory, name)))]));
}

export function validateReplacement(p, sourceManifest) {
  const source = sourceManifest.plan;
  ensure(source?.chainId === p.chainId && same(source.contracts?.AutomataDcapAttestationV2, p.legacyFee),
    'Replacement source manifest/chain mismatch');
  ensure(same(source.contracts.PCCSRouterV2, p.legacyRouter), 'Replacement Router differs from source manifest');
  ensure(p.programs.every(x => x.backend === 1), 'Replacement programs must contain only new RISC Zero builds');
  ensure(JSON.stringify(p.sourceSp1Provenance) === JSON.stringify(sp1Provenance(sourceManifest)),
    'Preserve original SP1 build provenance exactly');
  ensure(!p.deploySp1Groth16V6, 'Replacement must reuse the SP1 verifier');
  ensure(p.programs.some(x => x.backend === 1 && !x.minCheck)
    && p.programs.some(x => x.backend === 1 && x.minCheck), 'Replacement requires repaired strict and minimal RISC Zero programs');
}

export function sp1Provenance(manifest) {
  return manifest.migratedSp1
    ? manifest.migratedSp1.programs.map(x => x.buildProvenance).filter(Boolean)
    : manifest.plan.programs.filter(x => x.backend === 2);
}

// A complete event history is required: a selector mapping has no enumerable getter.
export async function readSp1Routes(p, rpc) {
  const receipt = await rpc.receipt(p.sourceDeploymentTx);
  ensure(receipt && BigInt(receipt.status) === 1n && same(receipt.contractAddress, p.legacyFee),
    'Missing source entrypoint deployment receipt');
  const routes = new Map();
  for (const event of await rpc.routeEvents(p.legacyFee, receipt.blockNumber)) {
    if (event.backend !== 2) continue;
    ensure(!event.removed, 'Removed route event');
    const selector = event.selector.toLowerCase();
    ensure(/^0x[0-9a-f]{8}$/.test(selector), 'Invalid route selector event');
    ensure(routes.get(selector)?.verifier !== frozenRoute, 'Route changed after permanent freeze');
    routes.set(selector, {selector, verifier: event.frozen ? frozenRoute : event.verifier.toLowerCase()});
  }
  const result = [...routes.values()].sort((a, b) => a.selector.localeCompare(b.selector));
  for (const route of result) {
    ensure(same(await rpc.route(p.legacyFee, 2, route.selector), route.verifier), 'SP1 route history/readback mismatch');
    if (route.verifier !== frozenRoute) {
      const code = await rpc.code(route.verifier);
      ensure(code !== '0x', 'SP1 route verifier has no code');
      route.runtimeSha256 = digest(Buffer.from(code.slice(2), 'hex'));
    }
  }
  return result;
}

export async function readReplacementState(p, legacy, rpc) {
  const sp1 = legacy.backends[2];
  ensure(!await rpc.call(p.legacyFee, 'zkV2Paused()', 'bool'),
    'Source V2 ZK is paused; review separately before replacement');
  ensure(sp1.code !== '0x' && sp1.ids.length > 0, 'Source SP1 must remain enabled');
  const programs = [];
  for (const id of sp1.ids) {
    const [registered, minCheck] = await rpc.call(p.legacyFee, 'programModeV2(uint8,bytes32)', 'bool,bool', 2, id);
    ensure(registered, 'Source SP1 mode missing');
    const buildProvenance = p.sourceSp1Provenance.find(x => same(x.id, id)) ?? null;
    ensure(!buildProvenance || buildProvenance.minCheck === minCheck, 'Source SP1 mode differs from build provenance');
    programs.push({id, minCheck, buildProvenance});
  }
  ensure(programs.some(x => same(x.id, sp1.defaultId) && !x.minCheck), 'Source SP1 default is not registered strict');
  // Reuse the audited v6 verifier, not a v5 route or an unreviewed replacement implementation.
  await rpc.verifyArtifact('SP1Groth16VerifierV6', sp1.code);
  const selector = (await rpc.call(sp1.verifier, 'VERIFIER_HASH()', 'bytes32')).slice(0, 10);
  const routes = await readSp1Routes(p, rpc);
  ensure(same(await rpc.route(p.legacyFee, 2, selector), sp1.verifier), 'Source SP1 v6 route is unavailable');
  const runtimeSha256 = {};
  for (const [name, address] of Object.entries(p.reusedContracts)) {
    const code = await rpc.code(address);
    ensure(code !== '0x', `Missing reused contract ${name}`);
    runtimeSha256[name] = digest(Buffer.from(code.slice(2), 'hex'));
  }
  for (const version of [3, 4, 5]) ensure(same(legacy.verifiers[version], p.reusedContracts[`V${version}QuoteVerifierV2`]),
    'Source quote verifier changed');
  ensure(same(legacy.router.pckHelperAddr, p.reusedContracts.PCKHelperV2), 'Source PCK helper changed');
  await rpc.verifyRouterLayout(p.legacyRouter, true);
  const restriction = await rpc.storage(p.legacyRouter, '0x1');
  const readers = {};
  for (const address of [p.legacyFee, ...Object.values(legacy.verifiers)]) {
    readers[address] = await rpc.authorized(p.legacyRouter, address);
    ensure((BigInt(restriction) & 255n) === 0n || readers[address], 'Source Router authorization missing');
  }
  // No Storage write is allowed for entrypoint replacement.
  const storages = {};
  for (const dao of [legacy.router.tcbEvalDaoAddr, legacy.router.pcsDaoAddr, legacy.router.pckDaoAddr,
    ...Object.values(legacy.evaluations).flatMap(x => Object.values(x))]) {
    const resolver = await rpc.call(dao, 'resolver()', 'address');
    ensure(await rpc.call(resolver, 'isAuthorizedCaller(address)', 'bool', p.legacyRouter), 'Existing Router lacks Storage permission');
    storages[resolver] = await rpc.call(resolver, 'owner()', 'address');
  }
  return {sp1: {programs, defaultId: sp1.defaultId, verifier: sp1.verifier, selector, routes},
    runtimeSha256, restriction, readers, storages};
}

export async function verifyReplacement(p, before, rpc) {
  const target = p.contracts.AutomataDcapAttestationV2;
  ensure(!same(target, p.legacyFee), 'Replacement aliases source entrypoint');
  for (const [name, address] of Object.entries(p.reusedContracts)) {
    ensure(same(p.contracts[name], address), 'Reused address changed');
    ensure(digest(Buffer.from((await rpc.code(address)).slice(2), 'hex')) === before.migration.runtimeSha256[name],
      'Reused contract runtime changed');
  }
  const runtime = await rpc.code(target);
  await rpc.verifyArtifact('AutomataDcapAttestationV2', runtime);
  ensure(same(await rpc.call(target, 'owner()', 'address'), p.owner), 'New owner mismatch');
  ensure(String(await rpc.call(target, 'getBp()', 'uint16')) === before.feeBp, 'Fee mismatch');
  ensure(!await rpc.call(target, 'zkV2Paused()', 'bool'), 'Replacement remains paused');
  ensure(await rpc.authorized(p.legacyRouter, target), 'New entrypoint lacks Router authorization');
  for (const version of [3, 4, 5]) ensure(same(await rpc.call(target, 'quoteVerifiers(uint16)', 'address', version),
    before.verifiers[version]), 'Replacement quote verifier mismatch');
  for (const backend of [1, 2, 3]) {
    const programs = backend === 2 ? before.migration.sp1.programs : p.programs.filter(x => x.backend === backend);
    const ids = await rpc.call(target, 'programIdentifiersV2(uint8)', 'bytes32[]', backend);
    ensure(ids.length === programs.length && ids.every(id => programs.some(x => same(x.id, id))), 'Replacement ID inventory mismatch');
    ensure(same(await rpc.call(target, 'programIdentifierV2(uint8)', 'bytes32', backend),
      (backend === 2 ? before.migration.sp1.defaultId : programs.find(x => !x.minCheck)?.id) ?? '0x' + '0'.repeat(64)), 'Replacement default ID mismatch');
    ensure(same(await rpc.call(target, 'zkVerifierV2(uint8)', 'address', backend),
      (backend === 2 ? before.migration.sp1.verifier : programs[0]?.verifier) ?? '0x' + '0'.repeat(40)), 'Replacement default verifier mismatch');
    for (const program of programs) {
      const [registered, minCheck] = await rpc.call(target, 'programModeV2(uint8,bytes32)', 'bool,bool', backend, program.id);
      ensure(registered && minCheck === program.minCheck, 'Replacement program mode mismatch');
      if (backend !== 2) ensure(same(await rpc.route(target, backend, program.proofSelector), program.verifier), 'Replacement proof route mismatch');
    }
  }
  ensure(same(await rpc.route(target, 2, before.migration.sp1.selector), before.migration.sp1.verifier), 'SP1 v6 route mismatch');
  for (const route of before.migration.sp1.routes) ensure(same(await rpc.route(target, 2, route.selector), route.verifier),
    'SP1 route/freeze was not preserved');
  for (const selector of ['0x00000000', '0x73c457ba', '0xbb001d44', '0x242f9d5b', '0x8b38038c']) {
    ensure(same(await rpc.route(target, 1, selector), '0x' + '0'.repeat(40)), 'Unapproved RISC Zero route/fallback');
  }
  return {runtimeSha256: {...before.migration.runtimeSha256,
    AutomataDcapAttestationV2: digest(Buffer.from(runtime.slice(2), 'hex'))}, readerStorages: Object.keys(before.migration.storages)};
}
