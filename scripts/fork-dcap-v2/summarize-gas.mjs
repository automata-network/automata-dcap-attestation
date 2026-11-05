#!/usr/bin/env node
// Compact derivative of already verified local reports. No RPC or write beyond
// a new output file. Full receipts/traces can remain outside Git.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
const [positiveFile,comparisonFile,output,...negativeFiles]=process.argv.slice(2);
if(!output || fs.existsSync(output))throw new Error('Usage: summarize-gas.mjs POSITIVE_GAS_REPORT COMPARISON_REPORT NEW_REPORT [NEGATIVE_REPORT ...]');
const read=file=>JSON.parse(fs.readFileSync(file));
const sha=file=>crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const positive=read(positiveFile),comparison=read(comparisonFile),negatives=negativeFiles.map(read);
if(positive.status!=='PASS'||positive.chainId!==11155111||positive.forkBlock!==11689923||positive.hardfork!=='Osaka'||
   comparison.status!=='PASS'||!comparison.snapshotRestored||comparison.rollbackChecks!=='PASS'||
   comparison.origin?.environment?.chainId!==11155111||comparison.origin?.forkConfig?.forkBlockNumber!==11689923||
   negatives.some(n=>n.status!=='PASS'||!n.snapshotRestored||n.chainId!==11155111||n.forkBlock!==11689923))throw new Error('Passing same-origin reports required');
function component(label) {
  if(label==='entrypoint + transaction accounting residual')return 'entrypointAndTransactionAccounting';
  if(/^V[345]QuoteVerifier$/.test(label))return 'quoteVerifierExclusive';
  if(label==='PCKHelper')return 'pckParser';
  if(label==='PCCSRouter')return 'router';
  if(label==='P256 precompile')return 'p256';
  if(label==='SHA256 precompile')return 'sha256';
  if(label.startsWith('BN254 '))return 'bn254';
  if(label.startsWith('RISC Zero ')||label.startsWith('SP1 '))return 'universalAndSnarkVerifierExclusive';
  if(label==='crlHelperAddr')return 'crlHelper';
  if(label==='fmspcTcbHelperAddr'||label.includes('FmspcTcbHelper'))return 'tcbHelpers';
  if(label.includes('DaoStorage'))return 'collateralStorage';
  if(label.includes('Dao')||label.endsWith('DaoAddr'))return 'collateralDaos';
  if(label==='transaction caller / refund recipient')return 'refundRecipient';
  return 'other';
}
const positiveRows=positive.results.map(row=>{
  const components={};
  for(const b of row.buckets){const name=component(b.label);components[name]=(components[name]||0)+b.residualGas;}
  if(Object.values(components).reduce((a,b)=>a+b,0)!==row.gasUsed||row.traceReconciliation!=='PASS')throw new Error('Gas decomposition does not reconcile');
  return {label:row.label,transactionHash:row.hash,gasUsed:row.gasUsed,calldataBytes:row.calldataBytes,
    standardIntrinsicGas:row.standardIntrinsicGas,calldataGas:row.calldataGas,dataFloorGas:row.dataFloorGas,
    ...(row.journalMetadata?{journal:row.journalMetadata}:{}),components};
});
// SDK labels must distinguish every version/body/backend/overload. A compact
// artifact must not silently collapse two different proof-input cells.
if(new Set(positiveRows.map(r=>r.label)).size!==positiveRows.length)throw new Error('Ambiguous or duplicate positive labels');
const result={schema:1,status:'MEASURED_LOCAL_GAS_NOT_RELEASE_APPROVAL',chainId:11155111,forkBlock:11689923,hardfork:'Osaka',
  sourceReports:[positiveFile,comparisonFile,...negativeFiles].map(file=>({file:path.basename(file),sha256:sha(file)})),
  scope:'Receipt gas on one pinned local Sepolia fork. No public transactions, L2 fees, market prices or worst-case gas guarantee.',
  accounting:'Components are exclusive call-tree residuals that sum to receipt gas. Intrinsic/calldata fields are a separate view and must not be added again. Entrypoint residual includes output/event/fee work plus transaction refund/floor accounting; quoteVerifierExclusive groups internal parsing/certificate/TCB work not separable by call tracing. This is not a per-source-function profiler.',
  positiveTransactions:positiveRows,
  rawLegacyComparison:comparison.comparisons,
  coldWarm:comparison.results.filter(r=>r.samples?.length===2).map(r=>({label:r.label,transactionGas:r.gasUsed,samples:r.samples})),
  coldWarmMeaning:'First and repeated actual calls within one test-only probe transaction, including call/payment overhead. Not standalone cold/warm transaction prices.',
  rollbackSnapshotRestored:true,
  negativeRuns:negatives.map(r=>({backend:r.backend,proofIdentity:r.proofIdentity||null,snapshotRestored:r.snapshotRestored,
    transactions:r.results.map(t=>({label:t.label,gasLimit:t.gasLimit,gasUsed:t.gasUsed,reverted:t.reverted,accepted:t.accepted,acceptedEvents:t.acceptedEvents}))})),
};
fs.writeFileSync(output,JSON.stringify(result,null,2)+'\n',{flag:'wx'});
console.log(`Compact gas summary: ${positiveRows.length} positive transactions, ${result.coldWarm.length} cold/warm pairs, ${result.negativeRuns.length} negative runs.`);
