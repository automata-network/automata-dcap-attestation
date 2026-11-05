#!/usr/bin/env node
// Recover a real public legacy proof without committing the full source logs.
// Read-only: cryptographic acceptance and present-state legacy behavior are
// separate results. This is not an ATKJ or V2 proof fixture. Compact V2
// exposes no legacy selectors, so legacy behavior is checked on the
// independent legacy contract only, plus explicit disabled-selector negatives
// on the V2 address.
import fs from 'node:fs';
import crypto from 'node:crypto';
import {execFileSync} from 'node:child_process';
const [deploymentFile, output] = process.argv.slice(2);
if (!output || fs.existsSync(output)) throw new Error('Usage: legacy-sp1-replay.mjs LOCAL_DEPLOYMENT NEW_REPORT.json');
const deployment = JSON.parse(fs.readFileSync(deploymentFile));
const endpoint = new URL(deployment.rpc);
if (deployment.status !== 'DEPLOYMENT_AND_COLLATERAL_TRANSACTIONS_PASS' || endpoint.protocol !== 'http:' || endpoint.hostname !== '127.0.0.1' || endpoint.username || endpoint.password) throw new Error('Completed local Anvil deployment only');
const sourceRpc = 'https://rpc.sepolia.ethpandaops.io';
const sourceTransaction = '0x77eb616e2eced89e1005f5df8f026b888ac96438c01ec2265bf9e795f1241db1';
const sourceBlock = 9902908;
const legacy = '0x27188aba3a26cbb806ef4c67de9b05d7d792ec10';
const gateway = '0x397a5f7f3dbd538f23de225b51f532c34448da9b';
const expectedId = '0x008228a87e56a065fb3ad27026aef08acc97d72d289439e8dab0d53baaea9f26';
const cast = (...args) => execFileSync('cast', args, {encoding: 'utf8', maxBuffer: 4 * 1024 * 1024}).trim();
const encode = (sig, ...args) => cast('calldata', sig, ...args.map(String));
const decode = (types, hex) => JSON.parse(cast('abi-decode', '--json', `f()(${types})`, hex));
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
async function rpc(url, method, params = []) {
  if (!['anvil_nodeInfo', 'eth_chainId', 'eth_getBlockByNumber', 'eth_getTransactionByHash', 'eth_getTransactionReceipt', 'eth_call'].includes(method)) throw new Error('Read-only methods only');
  const response = await fetch(url, {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({jsonrpc: '2.0', id: 1, method, params}), signal: AbortSignal.timeout(45000)});
  const body = await response.json();
  if (body.error) { const error = new Error(body.error.message); error.rpc = body.error; throw error; }
  return body.result;
}
const report = {schema: 1, status: 'IN_PROGRESS', sourceTransaction, sourceBlock, forkBlock: 11689923, writes: false,
  limitations: 'Public full-output legacy SP1 proof, not ATKJ or V2. Current collateral acceptance is reported separately; transport failures are not accepted rejections. No live or local transactions are sent.'};
const save = () => fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n');
save();
try {
  const info = await rpc(endpoint, 'anvil_nodeInfo'), before = await rpc(endpoint, 'eth_getBlockByNumber', ['latest', false]);
  if (info.environment?.chainId !== 11155111 || info.forkConfig?.forkBlockNumber !== 11689923 || Number(BigInt(await rpc(sourceRpc, 'eth_chainId'))) !== 11155111 || deployment.legacy.AutomataDcapAttestationFee.toLowerCase() !== legacy) throw new Error('Wrong chain, pin or legacy address');
  const tx = await rpc(sourceRpc, 'eth_getTransactionByHash', [sourceTransaction]);
  const receipt = await rpc(sourceRpc, 'eth_getTransactionReceipt', [sourceTransaction]);
  if (tx?.hash !== sourceTransaction || Number(BigInt(tx.blockNumber)) !== sourceBlock || receipt?.transactionHash !== sourceTransaction || receipt.blockHash !== tx.blockHash || BigInt(receipt.status) !== 1n || tx.to.toLowerCase() !== '0xe626f5503b455f775aa9845843b46033a26a635d' || !tx.input.startsWith('0x4a231d6f')) throw new Error('Unexpected source transaction/receipt');
  const bytes = Buffer.from(tx.input.slice(2), 'hex');
  const word = (b, offset) => {
    if (offset < 0 || offset + 32 > b.length) throw new Error('ABI word bounds');
    const n = BigInt('0x' + b.subarray(offset, offset + 32).toString('hex'));
    if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('ABI size overflow');
    return Number(n);
  };
  const dynamic = (b, base, slot) => {
    const at = base + word(b, base + 32 * slot), size = word(b, at);
    if (at + 32 + size > b.length) throw new Error('ABI bytes bounds');
    return b.subarray(at + 32, at + 32 + size);
  };
  if (word(bytes, 68) !== 2) throw new Error('Wrong backend');
  const envelope = dynamic(bytes, 4, 3), tuple = word(envelope, 0);
  const journal = dynamic(envelope, tuple, 0), proof = dynamic(envelope, tuple, 1);
  const topic = cast('keccak', 'AttestationSubmitted(bool,uint8,bytes)');
  const logs = receipt.logs.filter(l => l.address.toLowerCase() === legacy && l.topics[0] === topic);
  if (logs.length !== 1) throw new Error('Unexpected canonical fee events');
  const event = Buffer.from(logs[0].data.slice(2), 'hex'), expectedOutput = dynamic(event, 0, 2);
  if (word(event, 0) !== 1 || word(event, 32) !== 2 || journal.length !== 2 + expectedOutput.length + 8 + 192 || journal.readUInt16BE(0) !== expectedOutput.length || !journal.subarray(2, 2 + expectedOutput.length).equals(expectedOutput) || proof.length !== 260 || proof.subarray(0, 4).toString('hex') !== 'a4594c59') throw new Error('Journal/proof/source event mismatch');
  const id = await rpc(sourceRpc, 'eth_call', [{to: legacy, data: encode('programIdentifier(uint8)', 2)}, tx.blockNumber]);
  if (id !== expectedId) throw new Error('Unexpected historical program ID');
  const call = (to, data) => rpc(endpoint, 'eth_call', [{to, data, gas: '0xb71b00'}, before.number]);
  const journalHex = '0x' + journal.toString('hex'), proofHex = '0x' + proof.toString('hex');
  await call(gateway, encode('verifyProof(bytes32,bytes,bytes)', id, journalHex, proofHex));
  Object.assign(report, {sourceBlockHash: tx.blockHash, sourceCalldataSha256: sha(bytes), readbackBlock: {number: before.number, hash: before.hash}, programId: id, gateway, gatewayCrypto: 'PASS', journalSha256: sha(journal), proofSha256: sha(proof), journalBytes: journal.length, proofBytes: proof.length, quoteVersion: journal.readUInt16BE(2), quoteBodyType: journal.readUInt16BE(4), verificationTimestamp: journal.readBigUInt64BE(2 + expectedOutput.length).toString(), atkJGuardAndMagicPresent: expectedOutput.subarray(11, 27).equals(Buffer.alloc(16)) && expectedOutput.subarray(27, 31).toString('hex') === '41544b4a', negatives: [], replay: []});
  const flip = (hex, index) => { const b = Buffer.from(hex.slice(2), 'hex'); b[index] ^= 1; return '0x' + b.toString('hex'); };
  const revertOnly = error => {
    if (!error.rpc || error.rpc.code !== 3 || typeof error.rpc.data !== 'string' || !error.rpc.data.startsWith('0x')) throw error;
    return error.rpc.data;
  };
  for (const [name, key, j, p] of [['wrong-id', flip(id, 31), journalHex, proofHex], ['modified-journal', id, flip(journalHex, 25), proofHex], ['modified-proof', id, journalHex, flip(proofHex, 259)]]) {
    let revertData;
    try { await call(gateway, encode('verifyProof(bytes32,bytes,bytes)', key, j, p)); } catch (error) { revertData = revertOnly(error); }
    if (!revertData) throw new Error(name + ': unexpectedly accepted');
    report.negatives.push({name, status: 'REJECTED', revertData});
  }
  // Compact V2 deliberately exposes no legacy selectors. The independent legacy
  // contract keeps its own behavior; the V2 address must reject the old entrypoints.
  const v2 = deployment.contracts.AutomataDcapAttestationV2.address;
  report.legacySelectorsDisabledOnV2 = [];
  for (const [name, selector] of [['verifyAndAttestOnChain(bytes,uint32)', '0x1beaf6d8'],
    ['verifyAndAttestWithZKProof(bytes,uint8,bytes,bytes32,uint32)', '0x6199c20a']]) {
    let revertData;
    try { await rpc(endpoint, 'eth_call', [{to: v2, data: selector + '00'.repeat(36)}, before.number]); }
    catch (error) { revertData = revertOnly(error); }
    if (!revertData) throw new Error(name + ': legacy selector unexpectedly present on V2');
    report.legacySelectorsDisabledOnV2.push({name, selector, status: 'REJECTED'});
  }
  for (const evaluation of [0, 17, 18, 19, 20, 21]) {
    const data = encode('verifyAndAttestWithZKProof(bytes,uint8,bytes,bytes32,uint32)', journalHex, 2, proofHex, id, evaluation);
    let wire;
    try { wire = await call(legacy, data); } catch (error) { report.replay.push({evaluation, legacy: {reverted: true, revertData: revertOnly(error)}}); continue; }
    const [success, output] = decode('bool,bytes', wire);
    if (success && output !== '0x' + expectedOutput.toString('hex')) throw new Error('Accepted output differs from the authenticated source event');
    report.replay.push({evaluation, legacy: {reverted: false, success, output}});
  }
  if ((await rpc(endpoint, 'eth_getBlockByNumber', ['latest', false])).hash !== before.hash) throw new Error('Concurrent local writes');
  report.status = 'GATEWAY_CRYPTO_AND_CURRENT_LEGACY_PARITY_PASS'; save();
  console.log(`${report.status}: 3 crypto negatives, 2 disabled-selector V2 checks, 6 legacy cases; accepted legacy cases=${report.replay.filter(r => r.legacy.success).length}; ATKJ=${report.atkJGuardAndMagicPresent}`);
} catch (error) { report.status = 'FAILED'; report.error = error.message; save(); throw error; }
