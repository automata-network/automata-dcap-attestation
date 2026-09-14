#!/usr/bin/env node
// Offline reconciliation of the six scoped real-proof cells. This consumes
// receipt/trace-derived reports, not untrusted claims as a proof verifier.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const [summaryFile, output, ...proofFiles] = process.argv.slice(2);
if (!output || proofFiles.length !== 6 || fs.existsSync(output)) throw new Error('Usage: proof-matrix.mjs FINAL_GAS_SUMMARY NEW_REPORT SIX_VERIFIED_EVM_PROOFS');
const read = file => JSON.parse(fs.readFileSync(file));
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const summary = read(summaryFile);
if (summary.status !== 'MEASURED_LOCAL_GAS_NOT_RELEASE_APPROVAL' || summary.chainId !== 11155111 || summary.forkBlock !== 11689923 || !summary.rollbackSnapshotRestored || summary.hardfork !== 'Osaka') throw new Error('Passing final Sepolia gas summary required');
const programs = {
  1: {id: '0x9d4a47be495ab06a6a84b24d856a13a68312d8fdea487bcb8aa6931a322f9b9b', selector: '0x73c457ba', backend: 'RISC Zero'},
  2: {id: '0x000544ec0a86e3860bac6c329267c270beed1f7be600519128022a02f4b9f170', selector: '0xa4594c59', backend: 'SP1'},
};
const fixtures = ['ata-sgx-v3', 'ata-tdx-v4', 'v5'].map(name => ({name, ...read(path.join(root, `evm/forge-test/assets/v2/fixtures/${name}.json`))}));
const cells = [], seen = new Set();
for (const file of proofFiles) {
  const proof = read(file), program = programs[proof.backend];
  if (proof.localVerification !== 'PASS' || !program || proof.programId !== program.id || !/^0x[0-9a-f]{520}$/.test(proof.proof) || !proof.proof.startsWith(program.selector)) throw new Error('Unexpected verified program/proof');
  const fixture = fixtures.find(f => f.expectedJournal === proof.journal);
  if (!fixture) throw new Error('Proof journal differs from all frozen signed fixtures');
  const journal = Buffer.from(proof.journal.slice(2), 'hex');
  const version = journal.readUInt16BE(5), body = journal.readUInt16BE(7);
  const key = `${proof.backend}.quote-v${version}.body-${body}`;
  if (seen.has(key)) throw new Error('Duplicate real-proof matrix cell');
  seen.add(key);
  const journalSha256 = sha(journal), proofSha256 = sha(Buffer.from(proof.proof.slice(2), 'hex'));
  const rows = summary.positiveTransactions.filter(r => r.journal?.backend === proof.backend && r.journal?.quoteVersion === version && r.journal?.quoteBodyType === body);
  if (rows.length !== 4) throw new Error(key + ': requires Go and Rust, explicit and automatic transactions');
  const labels = new Set(rows.map(r => r.label));
  for (const sdk of ['go', 'rust']) for (const overload of ['explicit', 'default']) {
    if (!labels.has(`${sdk}-sdk.zk.backend-${proof.backend}.quote-v${version}.body-${body}.${overload}`)) throw new Error(key + ': SDK/overload missing');
  }
  for (const row of rows) {
    if (row.journal.journalSha256 !== journalSha256 || row.journal.programId !== program.id || row.journal.proofSelector !== program.selector || row.journal.proofSha256 !== proofSha256 || row.journal.journalBytes !== journal.length) throw new Error(key + ': confirmed transaction does not bind this exact proof/journal/program');
  }
  const negatives = summary.negativeRuns.filter(r => r.backend === proof.backend && r.proofIdentity?.quoteVersion === version && r.proofIdentity?.quoteBodyType === body);
  if (negatives.length !== 1) throw new Error(key + ': unique transaction-negative run required');
  const negative = negatives[0], identity = negative.proofIdentity;
  if (!negative.snapshotRestored || identity.journalSha256 !== journalSha256 || identity.proofSha256 !== proofSha256 || identity.programId !== program.id || identity.proofSelector !== program.selector) throw new Error(key + ': negative-run proof association mismatch');
  const rejected = negative.transactions.filter(t => t.label.startsWith('raw.') || t.label.startsWith('zk.'));
  if (rejected.length !== 11 || rejected.some(t => t.accepted || t.acceptedEvents !== 0)) throw new Error(key + ': expected 11 rejected transactions');
  const controls = negative.transactions.filter(t => t.label.startsWith('baseline.'));
  if (controls.length !== 2 || controls.some(t => t.reverted || !t.accepted || t.acceptedEvents !== 1)) throw new Error(key + ': missing positive negative-test controls');
  const warm = summary.coldWarm.filter(r => r.label === `cold-warm.zk.${key}`);
  if (warm.length !== 1 || warm[0].samples.length !== 2 || warm[0].samples[0].outputHash !== warm[0].samples[1].outputHash) throw new Error(key + ': cold/warm pair missing');
  cells.push({backend: program.backend, fixture: fixture.name, quoteVersion: version, quoteBodyType: body, verificationTimestamp: fixture.verificationTimestamp, quoteSha256: fixture.quoteSha256, programId: program.id, proofSelector: program.selector, evmProofJsonSha256: sha(fs.readFileSync(file)), proofSha256, journalSha256, journalBytes: journal.length, sdkTransactions: rows.map(r => ({label: r.label, transactionHash: r.transactionHash, gasUsed: r.gasUsed})), rejectionTransactions: rejected.length, coldWarmCallGas: warm[0].samples.map(s => Number(s.callGas)), status: 'PASS'});
}
if (seen.size !== 6 || summary.negativeRuns.length !== 6 || summary.positiveTransactions.length !== 63 || summary.coldWarm.length !== 15) throw new Error('Incomplete or expanded scoped matrix');
cells.sort((a, b) => a.backend.localeCompare(b.backend) || a.quoteVersion - b.quoteVersion);
const result = {schema: 1, status: 'SIX_REAL_PROOF_SDK_CELLS_RECONCILED_NOT_RELEASE_APPROVAL', chainId: 11155111, forkBlock: 11689923, summarySha256: sha(fs.readFileSync(summaryFile)), cells,
  limitations: 'Three supplied authenticated Platform CA fixtures (SGX V3, TDX V4, TDX 1.5 V5), two canonical Docker programs, Groth16 only. No missing SGX/TDX body combination, Processor CA, ATKJ, remote service, other-network or live rollout acceptance is inferred. This report reconciles previous cryptographic and on-chain runs; it is not itself a proof verifier.'};
fs.writeFileSync(output, JSON.stringify(result, null, 2) + '\n', {flag: 'wx'});
console.log('Six cells, 24 SDK proof transactions, 66 rejection transactions and six cold/warm proof pairs reconcile.');
