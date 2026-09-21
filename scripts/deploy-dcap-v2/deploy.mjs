#!/usr/bin/env node
// Isolated V2 deployment coordinator. No transaction without --broadcast.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync, spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {createRpcRequest, validatePlan, pendingSp1Verifier} from './publish-v2.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const evm = path.join(root, 'evm');
const ensure = (ok, msg) => { if (!ok) throw new Error(msg); };
const read = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const save = (file, value) => {
  fs.writeFileSync(file + '.pending', JSON.stringify(value, null, 2) + '\n', {mode: 0o600});
  fs.renameSync(file + '.pending', file);
};
const same = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();
export function redactError(message, url) {
  let text = String(message);
  if (url) {
    text = text.split(url).join('[REDACTED_RPC]');
    try {
      const parsed = new URL(url);
      for (const value of [parsed.username, parsed.password, ...parsed.searchParams.values(),
        ...parsed.pathname.split('/').filter(x => x.length >= 8)].filter(Boolean)) {
        text = text.split(value).join('[REDACTED]');
      }
    } catch { /* No endpoint details in the generic error. */ }
  }
  return text.replace(/https?:\/\/[^\s"'<>]+/gi, '[REDACTED_URL]');
}
const capture = (bin, args, cwd = root) => execFileSync(bin, args, {cwd, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024}).trim();
const run = (bin, args, cwd = root) => {
  const result = spawnSync(bin, args, {cwd, stdio: 'inherit'});
  ensure(result.status === 0, `${bin} failed; saved checkpoint retained`);
};

export function evaluationInventory(registry) {
  return [...new Set(Object.keys(registry).flatMap(key => {
    const m = key.match(/_tcbeval_(\d+)$/); return m ? [Number(m[1])] : [];
  }))].sort((a, b) => a - b);
}

export function deploymentContracts(transactions) {
  const names = {AutomataDcapAttestationV2: 'AutomataDcapAttestationV2',
    PCCSRouter: 'PCCSRouterV2', PCKHelper: 'PCKHelperV2',
    V3QuoteVerifier: 'V3QuoteVerifierV2', V4QuoteVerifier: 'V4QuoteVerifierV2', V5QuoteVerifier: 'V5QuoteVerifierV2'};
  const result = {};
  for (const tx of transactions) {
    const key = names[tx.contractName];
    if (tx.transactionType !== 'CREATE' || !key) continue;
    ensure(!result[key], `Duplicate deployment for ${key}`);
    ensure(/^0x[0-9a-f]{40}$/i.test(tx.contractAddress), `Missing deployment address for ${key}`);
    result[key] = tx.contractAddress;
  }
  ensure(Object.keys(result).length === 6, 'Expected six direct deployments');
  return result;
}

export async function readerInventory(legacy, call) {
  const daos = [legacy.router.tcbEvalDaoAddr, legacy.router.pcsDaoAddr, legacy.router.pckDaoAddr,
    ...Object.values(legacy.evaluations).flatMap(x => [x.qeIdDaoVersionedAddr, x.fmspcTcbDaoVersionedAddr])];
  const readers = new Map();
  for (const dao of daos) {
    const resolver = await call(dao, 'resolver()(address)');
    const owner = await call(resolver, 'owner()(address)');
    const key = resolver.toLowerCase();
    if (readers.has(key)) ensure(same(readers.get(key).owner, owner), 'Resolver owner changed');
    else readers.set(key, {dao, resolver, owner});
  }
  return [...readers.values()];
}

async function main() {
  const [configFile, runDirectory, ...flags] = process.argv.slice(2);
  ensure(configFile && runDirectory && flags.every(x => ['--broadcast', '--resume'].includes(x)),
    'Usage: node deploy.mjs CONFIG RUN_DIRECTORY [--broadcast] [--resume]');
  const live = flags.includes('--broadcast');
  const config = read(configFile);
  const out = path.resolve(runDirectory);
  fs.mkdirSync(out, {recursive: true});
  // Prevent two coordinators from sending transactions from the same checkpoint.
  const lock = path.join(out, 'coordinator.lock');
  const lockFd = fs.openSync(lock, 'wx', 0o600);
  try {
    const url = process.env.DCAP_RPC_URL;
    ensure(url, 'DCAP_RPC_URL required');
    const rpc = createRpcRequest(url);
    ensure(Number(BigInt(await rpc('eth_chainId'))) === config.chainId, 'Wrong RPC chain');
    const commit = capture('git', ['rev-parse', 'HEAD']);
    ensure(!capture('git', ['diff', 'HEAD', '--name-only']), 'Commit implementation changes before deployment');
    ensure(!capture('git', ['ls-files', '--others', '--exclude-standard']),
      'Untracked files are not part of the pinned source; commit implementation files and keep operator run files outside the repository');
    const stateFile = path.join(out, 'state.json');
    const configDigest = createHash('sha256').update(JSON.stringify(config)).digest('hex');
    const state = fs.existsSync(stateFile) ? read(stateFile) : {commit, configDigest, stages: {}, transactions: []};
    ensure(state.commit === commit && state.configDigest === configDigest, 'Checkpoint source/config changed');
    const checkpoint = () => save(stateFile, state);
    const planFile = path.join(out, 'plan.json');
    const beforeFile = path.join(out, 'before.json');
    const pinned = await rpc('eth_getBlockByNumber', ['finalized', false]);
    ensure(pinned?.number, 'Finalized RPC block required');
    const call = (to, sig, ...args) => capture('cast', ['call', to, sig, ...args.map(String), '--block', pinned.number, '--rpc-url', url]);
    let plan;
    if (fs.existsSync(planFile)) plan = read(planFile);
    else {
      const dir = path.join(root, 'rust-crates/libraries/network-registry/deployment/current', String(config.chainId));
      const dcap = read(path.join(dir, 'dcap.json')), pccs = read(path.join(dir, 'onchain_pccs.json'));
      const legacyRouter = dcap.PCCSRouter, legacyFee = dcap.AutomataDcapAttestationFee;
      const pcs = call(legacyRouter, 'pcsDaoAddr()(address)');
      plan = {status: 'TEST_ONLY', chainId: config.chainId, sourceCommit: commit, owner: config.owner,
        legacyRouter, legacyFee, p256: call(pcs, 'P256_VERIFIER()(address)'),
        evaluations: config.evaluations ?? evaluationInventory(pccs), programs: config.programs ?? [], transactions: [],
        deploySp1Groth16V6: config.deploySp1Groth16V6 === true};
      if (plan.deploySp1Groth16V6) for (const p of plan.programs.filter(p => p.backend === 2)) {
        ensure(!p.verifier || p.verifier === pendingSp1Verifier, 'Do not combine a supplied SP1 verifier with a new verifier deployment');
        p.verifier = pendingSp1Verifier;
      }
      validatePlan(plan, {allowPendingVerifier: true});
      save(planFile, plan);
    }
    validatePlan(plan, {allowPendingVerifier: true});
    const publisher = path.join(root, 'scripts/deploy-dcap-v2/publish-v2.mjs');
    if (!fs.existsSync(beforeFile)) run(process.execPath, [publisher, 'snapshot', planFile, beforeFile]);
    const before = read(beforeFile);
    const readers = await readerInventory(before.legacy, call);
    save(path.join(out, 'readers.json'), readers);
    const accountFor = owner => Object.entries(config.accounts ?? {}).find(([address]) => same(address, owner))?.[1];
    ensure(accountFor(plan.owner), 'Deployment owner needs a Foundry keystore in accounts');
    // Resolve all required EOAs before the first send. A multisig is deliberately
    // reported as a pending external authorization, never impersonated on a live chain.
    const pending = readers.filter(r => !accountFor(r.owner));
    save(path.join(out, 'pending-signers.json'), pending);
    if (live) ensure(pending.length === 0, 'Resolver owners missing from accounts; review pending-signers.json before broadcasting');
    run('forge', ['build'], evm);
    const script = 'forge-script/DeployDcapV2.s.sol:DeployDcapV2';
    const stage = async (name, owner, sig, args) => {
      if (state.stages[name]) return read(path.join(out, `${name}.broadcast.json`));
      const base = ['script', script, '--rpc-url', url, '--sender', owner, '--sig', sig, ...args.map(String)];
      if (!live) { run('forge', base, evm); return null; }
      if (state.running) ensure(state.running === name && flags.includes('--resume'),
        `Interrupted stage ${state.running}; inspect broadcast and rerun with --resume, never redeploy blindly`);
      else { run('forge', base, evm); state.running = name; checkpoint(); }
      const broadcastArgs = [...base, '--broadcast', '--slow', '--account', accountFor(owner)];
      if (flags.includes('--resume') && fs.existsSync(path.join(out, `${name}.started`))) broadcastArgs.push('--resume');
      fs.writeFileSync(path.join(out, `${name}.started`), 'Inspect Foundry broadcast before resuming.\n');
      run('forge', broadcastArgs, evm);
      // Foundry 1.5.1 names the broadcast artifact after the --sig function
      // (`<name>-latest.json`), not `run-latest.json`; older Foundry versions
      // wrote `run-latest.json` for every stage. Prefer the sig-named artifact
      // produced by the broadcast that just succeeded.
      const broadcastDir = path.join(evm, 'broadcast/DeployDcapV2.s.sol', String(plan.chainId));
      const sigName = `${sig.split('(')[0]}-latest.json`;
      const broadcast = read(fs.existsSync(path.join(broadcastDir, sigName))
        ? path.join(broadcastDir, sigName)
        : path.join(broadcastDir, 'run-latest.json'));
      save(path.join(out, `${name}.broadcast.json`), broadcast);
      state.transactions = [...new Set([...state.transactions, ...broadcast.transactions.map(t => t.hash).filter(Boolean)])];
      state.stages[name] = true; delete state.running; checkpoint();
      return broadcast;
    };
    const deployed = await stage('deploy', plan.owner,
      'deployIsolated(uint256,address,address,address,address,uint32[])',
      [plan.chainId, plan.owner, plan.legacyRouter, plan.legacyFee, plan.p256, JSON.stringify(plan.evaluations)]);
    let sp1Deployment;
    if (plan.deploySp1Groth16V6) {
      sp1Deployment = await stage('deploy-sp1-v6', plan.owner,
        'deploySp1Groth16V6(uint256,address)', [plan.chainId, plan.owner]);
    }
    if (!live) { console.log('PREFLIGHT/SIMULATION ONLY. No transaction or registry publication.'); return; }
    plan.contracts = deploymentContracts(deployed.transactions); save(planFile, plan);
    if (sp1Deployment) {
      const creates = sp1Deployment.transactions.filter(t => t.transactionType === 'CREATE' && t.contractName === 'SP1Groth16VerifierV6');
      ensure(creates.length === 1, 'Expected exactly one isolated SP1 v6 deployment');
      plan.sp1Groth16Verifier = creates[0].contractAddress;
      for (const p of plan.programs.filter(p => p.backend === 2)) p.verifier = plan.sp1Groth16Verifier;
      validatePlan(plan); save(planFile, plan);
    }
    const c = plan.contracts, attestation = c.AutomataDcapAttestationV2;
    for (const r of readers) await stage(`reader-${r.resolver.toLowerCase()}`, r.owner,
      'authorizeIsolatedReader(uint256,address,address,address,address)',
      [plan.chainId, r.owner, plan.legacyRouter, c.PCCSRouterV2, r.dao]);
    for (const p of [...plan.programs].sort((a, b) => Number(a.minCheck) - Number(b.minCheck))) {
      await stage(`backend-${p.backend}-${p.minCheck ? 'minimal' : 'strict'}`, plan.owner,
        p.minCheck ? 'configureMinimalProgram(address,address,uint8,bytes32)' : 'configureV2Backend(address,address,uint8,bytes32,address)',
        p.minCheck ? [plan.owner, attestation, p.backend, p.id] : [plan.owner, attestation, p.backend, p.id, p.verifier]);
    }
    if (plan.programs.length) await stage('enable-zk', plan.owner,
      'enableIsolatedZk(uint256,address,address,address,address,uint8[])',
      [plan.chainId, plan.owner, plan.legacyFee, plan.legacyRouter, attestation,
        JSON.stringify([...new Set(plan.programs.map(p => p.backend))])]);
    plan.transactions = state.transactions; save(planFile, plan);
    const finalized = await rpc('eth_getBlockByNumber', ['finalized', false]);
    for (const hash of state.transactions) {
      const receipt = await rpc('eth_getTransactionReceipt', [hash]);
      ensure(receipt && BigInt(receipt.status) === 1n, 'Transaction receipt missing/failed');
      if (BigInt(receipt.blockNumber) > BigInt(finalized.number)) {
        state.status = 'WAIT_FINALIZATION'; checkpoint();
        console.log('WAIT_FINALIZATION: rerun the same command later; completed stages will not resend.'); return;
      }
    }
    // Source verification is mandatory before registry publication; API key stays in environment.
    for (const tx of [...deployed.transactions, ...(sp1Deployment?.transactions ?? [])].filter(t => t.transactionType === 'CREATE')) {
      const key = `verified-${tx.contractAddress}`;
      if (state.stages[key]) continue;
      const artifact = capture('forge', ['inspect', tx.contractName, 'abi', '--json'], evm);
      const ctor = JSON.parse(artifact).find(x => x.type === 'constructor');
      // Etherscan verification needs an explicit compiler version; pinned
      // profiles leave it unset, so take it from the exact release artifact.
      const artifactFile = tx.contractName === 'SP1Groth16VerifierV6'
        ? path.join(evm, `out/${tx.contractName}.sol/${tx.contractName}.json`)
        : path.join(evm, `out_fork_osaka/${tx.contractName}.sol/${tx.contractName}.json`);
      const compiler = JSON.parse(fs.readFileSync(artifactFile)).metadata.compiler.version;
      const verifyArgs = ['verify-contract', tx.contractAddress, tx.contractName, '--chain', String(plan.chainId), '--watch', '--compiler-version', `v${compiler}`];
      if (ctor?.inputs.length) {
        const sig = `f(${ctor.inputs.map(x => x.type).join(',')})`;
        verifyArgs.push('--constructor-args', capture('cast', ['abi-encode', sig, ...tx.arguments]));
      }
      run('forge', verifyArgs, evm);
      state.stages[key] = true; checkpoint();
    }
    const report = path.join(out, 'readback.json');
    if (!state.stages.published) {
      run(process.execPath, [publisher, 'publish', planFile, beforeFile, report]);
      state.stages.published = true;
    }
    state.status = 'TEST_DEPLOYMENT_PUBLISHED_NOT_PROOF_ACCEPTANCE'; checkpoint();
    console.log(state.status);
  } finally { fs.closeSync(lockFd); fs.unlinkSync(lock); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(redactError(error.message, process.env.DCAP_RPC_URL)); process.exitCode = 1; });
}
