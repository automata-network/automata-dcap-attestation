#!/usr/bin/env node
// Scoped mitigation for the audited Sepolia V1.1 instance; dry-run unless --broadcast.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {createRpcRequest} from './publish-v2.mjs';

export const fee = '0x27188aba3a26cbb806ef4c67de9b05d7d792ec10';
export const owner = '0xdf841b239be7a6b37366005107069b7410da4ff9';
export const creationBlock = 8632335;
export const runtimeHash = '0xd52741a4626a99293e9d38f79ab890ac208953b1e26c2edf958163e0c2f001d0';
const zero = '0x' + '0'.repeat(40);
const word = '0x' + '0'.repeat(64);
const cast = (...args) => execFileSync('cast', args.map(String), {encoding: 'utf8', timeout: 30000}).trim();
const queries = [
  ['owner', 'owner()'], ['feeBp', 'getBp()'],
  ['risc0Verifier', 'zkVerifier(uint8)', 1], ['risc0Id', 'programIdentifier(uint8)', 1],
  ['risc0Ids', 'programIdentifiers(uint8)', 1], ['sp1Verifier', 'zkVerifier(uint8)', 2],
  ['sp1Id', 'programIdentifier(uint8)', 2], ['sp1Ids', 'programIdentifiers(uint8)', 2],
  ...[3, 4, 5].map(v => [`rawV${v}`, 'quoteVerifiers(uint16)', v]),
];

export async function readState(request) {
  assert.equal(BigInt(await request('eth_chainId')), 11155111n, 'Sepolia only');
  const block = await request('eth_getBlockByNumber', ['latest', false]);
  assert.ok(block?.hash && Number(BigInt(block.number)) >= creationBlock, 'Invalid block');
  assert.equal(cast('keccak', await request('eth_getCode', [fee, block.number])), runtimeHash, 'Unexpected Fee bytecode');
  const values = Object.fromEntries(await Promise.all(queries.map(async ([key, sig, ...args]) =>
    [key, (await request('eth_call', [{to: fee, data: cast('calldata', sig, ...args)}, block.number])).toLowerCase()])));
  assert.equal('0x' + values.owner.slice(-40), owner, 'Owner changed; review signer');
  assert.notEqual(values.risc0Id, word, 'Missing RISC Zero default ID');
  const ids = JSON.parse(cast('abi-decode', '--json', 'f()(bytes32[])', values.risc0Ids))[0];
  assert.ok(ids.includes(values.risc0Id), 'Default ID must already be registered');
  const calldata = cast('calldata', 'setZkConfiguration(uint8,(bytes32,address))', 1, `(${values.risc0Id},${zero})`);
  return {block, values, calldata};
}

export async function requireNoOverrides(request, toBlock, fromBlock = creationBlock) {
  // Any historical addition requires manual review, even if subsequently frozen.
  const topic = cast('keccak', 'ZkRouteAdded(uint8,bytes4,address)');
  for (let from = fromBlock; from <= toBlock; from += 30000) {
    const logs = await request('eth_getLogs', [{address: fee,
      fromBlock: '0x' + from.toString(16), toBlock: '0x' + Math.min(toBlock, from + 29999).toString(16),
      topics: [topic, '0x' + '1'.padStart(64, '0')]}]);
    assert.ok(Array.isArray(logs), 'Invalid route history response');
    assert.equal(logs.length, 0, 'RISC Zero explicit route history found; clearing the default alone is insufficient. Review/freeze routes separately.');
  }
}

async function requireCanonical(request, block) {
  assert.equal((await request('eth_getBlockByNumber', [block.number, false]))?.hash, block.hash, 'Block changed; rerun');
}

export function verifyDisabled(before, after) {
  assert.deepEqual(after.values, {...before.values, risc0Verifier: word}, 'Disable readback failed or unrelated configuration changed');
}

export async function main(args = process.argv.slice(2)) {
  assert.ok(args.length === 0 || (args.length === 2 && args[0] === '--broadcast' && args[1]),
    'Usage: node scripts/deploy-dcap-v2/disable-sepolia-v11-risc0.mjs [--broadcast FOUNDRY_KEYSTORE_NAME]');
  const url = process.env.DCAP_RPC_URL;
  assert.ok(url, 'DCAP_RPC_URL required');
  const request = createRpcRequest(url);
  const before = await readState(request);
  console.log(`Checking complete RISC Zero route history through block ${Number(BigInt(before.block.number))}...`);
  await requireNoOverrides(request, Number(BigInt(before.block.number)));
  await requireCanonical(request, before.block);
  if (before.values.risc0Verifier === word) {
    console.log('ALREADY_DISABLED; no transaction sent.');
    return;
  }
  await request('eth_call', [{from: owner, to: fee, data: before.calldata}, before.block.number]);
  console.log(JSON.stringify({chainId: 11155111, fee, owner, block: before.block.number,
    previousVerifier: '0x' + before.values.risc0Verifier.slice(-40), preservedProgramId: before.values.risc0Id,
    calldata: before.calldata}, null, 2));
  if (!args.length) {
    console.log('DRY_RUN_PASS; no transaction sent. Re-run with --broadcast FOUNDRY_KEYSTORE_NAME to disable.');
    return;
  }
  // Do not race other owner configuration changes while signing this transaction.
  const fresh = await readState(request);
  assert.deepEqual(fresh.values, before.values, 'Configuration changed; rerun');
  await requireNoOverrides(request, Number(BigInt(fresh.block.number)), Number(BigInt(before.block.number)));
  await requireCanonical(request, before.block);
  await requireCanonical(request, fresh.block);
  let receipt;
  try {
    receipt = JSON.parse(execFileSync('cast', ['send', fee, before.calldata,
      '--rpc-url', url, '--account', args[1], '--from', owner, '--confirmations', '2', '--json'],
    {encoding: 'utf8', stdio: ['inherit', 'pipe', 'inherit']}));
  } catch {
    throw new Error('Signing/send failed or receipt unavailable. Inspect the transaction before retrying; dry-run is safe to repeat.');
  }
  assert.equal(BigInt(receipt.status), 1n, 'Disable transaction reverted');
  console.log(`transactionHash=${receipt.transactionHash}`);
  const after = await readState(request);
  verifyDisabled(before, after);
  await requireNoOverrides(request, Number(BigInt(after.block.number)), Number(BigInt(before.block.number)));
  await requireCanonical(request, after.block);
  console.log('DISABLED_READBACK_PASS; RISC Zero verifier cleared; program IDs, raw/SP1 configuration, owner and fee unchanged.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
