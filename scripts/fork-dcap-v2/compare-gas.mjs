#!/usr/bin/env node
// Local-only transaction benchmark and isolation check. Uses real deployed
// verifiers and signed collateral; restores the complete starting snapshot.
// Compact V2: the isolated stack never reconfigures the shared legacy Router,
// so there is no helper rollback; isolation is verified read-only instead.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const [deploymentFile,output,...proofFiles]=process.argv.slice(2);
if(!output || fs.existsSync(output))throw new Error('Usage: compare-gas.mjs DEPLOYMENT_REPORT NEW_REPORT.json [VERIFIED_EVM_PROOF ...]');
const deployment=JSON.parse(fs.readFileSync(deploymentFile));
if(deployment.status!=='DEPLOYMENT_AND_COLLATERAL_TRANSACTIONS_PASS')throw new Error('Deployment required');
const endpoint=new URL(deployment.rpc);
if(endpoint.protocol!=='http:' || endpoint.hostname!=='127.0.0.1' || endpoint.username || endpoint.password)throw new Error('Literal local Anvil only');
const cast=(...args)=>execFileSync('cast',args,{encoding:'utf8',maxBuffer:8*1024*1024}).trim();
const encode=(sig,...args)=>cast('calldata',sig,...args.map(String));
const decode=(returns,wire)=>JSON.parse(cast('abi-decode','--json',`f()(${returns})`,wire));
async function rpc(method,params=[]) {
  if(!['anvil_nodeInfo','eth_getBlockByNumber','eth_call','eth_sendTransaction','eth_getTransactionReceipt','debug_traceTransaction','evm_snapshot','evm_revert','anvil_setBalance','anvil_impersonateAccount','anvil_stopImpersonatingAccount'].includes(method))throw new Error('Unexpected RPC');
  const r=await fetch(endpoint,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(60000)});
  const x=await r.json();if(x.error)throw new Error(JSON.stringify(x.error));return x.result;
}
const info=await rpc('anvil_nodeInfo'),origin=deployment.origin;
if(info.environment?.chainId!==11155111 || info.forkConfig?.forkBlockNumber!==11689923 || info.hardFork!=='Osaka' ||
   (info.network && info.network!=='ethereum') || origin.currentBlockHash!=='0x4ee0fcdc5b220406b457d0242cc280f0313ff1cc72bd5d9fdf041808881c8096')throw new Error('Wrong reviewed fork/runtime');
const fee=deployment.contracts.AutomataDcapAttestationV2.address,legacy=deployment.legacy.AutomataDcapAttestationFee;
const router=deployment.contracts.PCCSRouter.address,legacyRouter=deployment.legacy.PCCSRouter,owner=deployment.owner,actor='0x'+crypto.randomBytes(20).toString('hex');
const call=async(to,sig,returns,...args)=>decode(returns,await rpc('eth_call',[{from:actor,to,data:encode(sig,...args)},'latest']));
const keys=['tcbEvalDaoAddr','pcsDaoAddr','pckDaoAddr','pckHelperAddr','crlHelperAddr','fmspcTcbHelperAddr'];
const before=await rpc('eth_getBlockByNumber',['latest',false]),snapshot=await rpc('evm_snapshot');
const report={schema:1,status:'IN_PROGRESS',scope:'Same-Sepolia local transactions: legacy/V2 raw comparison, actual cold/warm calls and read-only isolation verification; test snapshot restored. Not production transactions or pure function-gas estimates. Legacy and compact V2 outputs intentionally differ in format and are not byte-compared.',origin:info,results:[],comparisons:[]};
const save=()=>fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n');save();
const sampleTopic=cast('keccak','Sample(uint256,uint256,bytes32)');
async function tx(label,to,input,{from=actor,admin=false,probe=false,creation=false}={}) {
  const hash=await rpc('eth_sendTransaction',[{from,...(to?{to}:{}),data:input,gas:'0xffffff',gasPrice:'0x3b9aca00',value:admin||creation?'0x0':probe?'0x2c68af0bb140000':'0x16345785d8a0000'}]);
  let receipt;
  for(let attempt=0;attempt<240;attempt++) {
    receipt=await rpc('eth_getTransactionReceipt',[hash]);
    if(receipt)break;
    await new Promise(resolve=>setTimeout(resolve,250));
  }
  if(!receipt)throw new Error(label+': receipt not available');
  const trace=await rpc('debug_traceTransaction',[hash,{tracer:'callTracer'}]);
  if(BigInt(receipt.status)!==1n){report.results.push({label,transactionHash:hash,status:'REVERTED',receipt,trace});save();throw new Error(label+': transaction reverted');}
  if(BigInt(trace.gasUsed)!==BigInt(receipt.gasUsed))throw new Error('Receipt/trace mismatch');
  let output;
  if(!admin && !probe && !creation){
    // Legacy raw returns (bool,bytes); compact V2 raw returns (bool,bytes,bytes).
    const tuple=sameAddress(to,fee)?'bool,bytes,bytes':'bool,bytes';
    const decoded=decode(tuple,trace.output);if(!decoded[0])throw new Error(label+': rejected');output=decoded[1];
  }
  const bytes=Buffer.from(input.slice(2),'hex'),zeros=bytes.filter(b=>b===0).length;
  const intrinsic=21000+4*zeros+16*(bytes.length-zeros)+(creation?32000+2*Math.ceil(bytes.length/32):0);
  const samples=receipt.logs.filter(l=>l.topics[0]===sampleTopic).map(l=>({index:Number(BigInt(l.topics[1])),...Object.fromEntries(decode('uint256,bytes32',l.data).map((v,i)=>[i===0?'callGas':'outputHash',v]))}));
  if(probe && (samples.length!==2 || samples[0].outputHash!==samples[1].outputHash))throw new Error('Probe outputs/sample count mismatch');
  const row={label,transactionHash:hash,gasUsed:Number(BigInt(receipt.gasUsed)),calldataBytes:bytes.length,standardIntrinsicGas:intrinsic,
    calldataGas:4*zeros+16*(bytes.length-zeros),dataFloorGas:21000+10*(zeros+4*(bytes.length-zeros)),samples,receipt,trace};
  report.results.push(row);save();console.log(`${label}: gas=${row.gasUsed}${probe?' cold/warm='+samples.map(s=>s.callGas).join('/') : ''}`);
  return {row,output};
}
const sameAddress=(a,b)=>String(a).toLowerCase()===String(b).toLowerCase();
const raw=(v2,f)=>encode(v2?'verifyAndAttestOnChainV2(bytes,uint32,bool)':'verifyAndAttestOnChain(bytes,uint32)',f.quote,f.tcbEvaluationDataNumber,...(v2?[false]:[]));
let failure;
try {
  for(const who of [actor,owner])await rpc('anvil_impersonateAccount',[who]);
  await rpc('anvil_setBalance',[actor,'0x56bc75e2d63100000']);
  const artifact=JSON.parse(fs.readFileSync(path.join(root,'evm/out_fork_osaka/ForkGasProbe.sol/ForkGasProbe.json')));
  if(artifact.metadata.settings.evmVersion!=='paris')throw new Error('Probe must use the same Paris build target');
  const {row:created}=await tx('test-only.deploy-gas-probe',null,artifact.bytecode.object,{creation:true});
  const probe=created.receipt.contractAddress;
  const fixtures=['ata-sgx-v3','ata-tdx-v4','v5'].map(name=>({name,...JSON.parse(fs.readFileSync(path.join(root,`evm/forge-test/assets/v2/fixtures/${name}.json`)))}));
  for(const f of fixtures) {
    const [legacyOk]=await call(legacy,'verifyAndAttestOnChain(bytes,uint32)','bool,bytes',f.quote,f.tcbEvaluationDataNumber);
    const [v2Ok]=await call(fee,'verifyAndAttestOnChainV2(bytes,uint32,bool)','bool,bytes,bytes',f.quote,f.tcbEvaluationDataNumber,false);
    if(!legacyOk||!v2Ok)throw new Error('Legacy/V2 raw availability mismatch');
    const costs={};
    for(const [kind,target,v2] of [['legacy',legacy,false],['v2',fee,true]]) {
      const input=raw(v2,f),{row,output}=await tx(`raw.${f.name}.${kind}`,target,input);
      costs[kind]=row.gasUsed;
      if(v2){
        const expected=Buffer.from(f.expectedJournal.slice(2),'hex'),block=await rpc('eth_getBlockByNumber',[row.receipt.blockNumber,false]);
        // Compact V2 journal timestamp lives at bytes 53..61.
        expected.writeBigUInt64BE(BigInt(block.timestamp),53);
        if(output!=='0x'+expected.toString('hex'))throw new Error('V2 journal mismatch');
      }
      await tx(`cold-warm.${f.name}.${kind}`,probe,encode('probe(address,bytes)',target,input),{probe:true});
    }
    report.comparisons.push({fixture:f.name,...costs,v2MinusLegacy:costs.v2-costs.legacy,v2DeltaPercent:100*(costs.v2-costs.legacy)/costs.legacy});save();
  }
  // No shared-state rollback exists in the isolated deployment. Verify
  // read-only that the legacy Router is untouched and both entries still work.
  for(let i=0;i<keys.length;i++)if(!sameAddress((await call(legacyRouter,keys[i]+'()','address'))[0],deployment.originalRouter[keys[i]]))throw new Error('Legacy Router was reconfigured');
  if(!sameAddress((await call(router,'pckHelperAddr()','address'))[0],deployment.contracts.PCKHelper.address))throw new Error('Isolated Router helper mismatch');
  for(const f of fixtures) {
    const [legacyOk]=await call(legacy,'verifyAndAttestOnChain(bytes,uint32)','bool,bytes',f.quote,f.tcbEvaluationDataNumber);
    const [v2Ok]=await call(fee,'verifyAndAttestOnChainV2(bytes,uint32,bool)','bool,bytes,bytes',f.quote,f.tcbEvaluationDataNumber,false);
    if(!legacyOk||!v2Ok)throw new Error('Raw availability changed after comparison');
  }
  report.rollbackChecks='PASS';
  if(proofFiles.length)await tx('admin.unpause-for-real-zk-probes',fee,encode('setZkV2Paused(bool)',false),{from:owner,admin:true});
  const measuredProofCells=new Set();
  for(const proofFile of proofFiles) {
    const p=JSON.parse(fs.readFileSync(proofFile));
    if(p.localVerification!=='PASS' || ![1,2].includes(p.backend))throw new Error('Verified production backend proof required');
    const journal=Buffer.from(p.journal.slice(2),'hex');
    if(journal.length<9 || journal.readUInt16BE(0)!==2 || journal.readUInt16BE(2)!==1 || journal[4]!==6)throw new Error('Unexpected V2 proof journal');
    const cell=`${p.backend}.quote-v${journal.readUInt16BE(5)}.body-${journal.readUInt16BE(7)}`;
    if(measuredProofCells.has(cell))throw new Error('Duplicate proof matrix cell');
    measuredProofCells.add(cell);
    const input=encode('verifyAndAttestWithZKProofV2(bytes,uint8,bytes,bytes32,uint32,bool)',p.journal,p.backend,p.proof,p.programId,20,false);
    await tx(`cold-warm.zk.${cell}`,probe,encode('probe(address,bytes)',fee,input),{probe:true});
  }
  if(proofFiles.length)await tx('admin.repause-after-real-zk-probes',fee,encode('setZkV2Paused(bool)',true),{from:owner,admin:true});
  report.isolationChecks='PASS';
}catch(error){failure=error;report.error=error.message;}
finally {
  try {
    for(const who of [actor,owner])await rpc('anvil_stopImpersonatingAccount',[who]);
    if(!await rpc('evm_revert',[snapshot]))throw new Error('Snapshot revert failed');
    if((await rpc('eth_getBlockByNumber',['latest',false])).hash!==before.hash)throw new Error('Snapshot readback failed');
    report.snapshotRestored=true;
  }catch(error){failure??=error;report.cleanupError=error.message;}
  report.status=failure?'FAILED':'PASS';save();
}
if(failure)throw failure;
console.log('Comparison/isolation complete; original local snapshot restored.');
