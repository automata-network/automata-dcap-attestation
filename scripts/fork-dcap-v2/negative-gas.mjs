#!/usr/bin/env node
// Isolated local transaction negatives. Snapshot restoration is a test reset,
// not a claim that an immutable production route freeze can be undone.
import fs from 'node:fs';
import crypto from 'node:crypto';
import {execFileSync} from 'node:child_process';
const [deploymentFile,fixtureFile,proofFile,output]=process.argv.slice(2);
if(!output || fs.existsSync(output))throw new Error('Usage: negative-gas.mjs ANVIL_REPORT FIXTURE VERIFIED_PROOF NEW_REPORT.json');
const deployment=JSON.parse(fs.readFileSync(deploymentFile)),fixture=JSON.parse(fs.readFileSync(fixtureFile)),payload=JSON.parse(fs.readFileSync(proofFile));
if(deployment.status!=='DEPLOYMENT_AND_COLLATERAL_TRANSACTIONS_PASS' || payload.localVerification!=='PASS' || ![1,2].includes(payload.backend))throw new Error('Verified inputs required');
if(payload.journal!==fixture.expectedJournal)throw new Error('Proof/fixture mismatch');
const endpoint=new URL(deployment.rpc);
if(endpoint.protocol!=='http:' || endpoint.hostname!=='127.0.0.1' || endpoint.username || endpoint.password)throw new Error('Loopback Anvil only');
const fee=deployment.contracts.AutomataDcapAttestationV2.address,owner=deployment.owner;
const actor='0x'+crypto.randomBytes(20).toString('hex');
const cast=(...args)=>execFileSync('cast',args,{encoding:'utf8',maxBuffer:4*1024*1024}).trim();
const data=(sig,...args)=>cast('calldata',sig,...args.map(String));
async function rpc(method,params=[]) {
  if(!['anvil_nodeInfo','anvil_setBalance','anvil_impersonateAccount','anvil_stopImpersonatingAccount','evm_snapshot','evm_revert','eth_getBlockByNumber','eth_call','eth_sendTransaction','eth_getTransactionReceipt','debug_traceTransaction'].includes(method))throw new Error('Unexpected RPC');
  const res=await fetch(endpoint,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(60000)});
  const body=await res.json();if(body.error)throw new Error(JSON.stringify(body.error));return body.result;
}
const info=await rpc('anvil_nodeInfo');
const forkPins={11155111:11689923,560048:3666000};
const chainId=deployment.origin?.environment?.chainId;
if(!forkPins[chainId] || info.environment?.chainId!==chainId || info.forkConfig?.forkBlockNumber!==forkPins[chainId])throw new Error('Wrong fork origin');
const before=await rpc('eth_getBlockByNumber',['latest',false]);
const snapshot=await rpc('evm_snapshot');
const report={schema:1,status:'IN_PROGRESS',chainId,forkBlock:forkPins[chainId],beforeBlock:before.hash,backend:payload.backend,
  proofIdentity:{programId:payload.programId,proofSelector:payload.proof.slice(0,10),proofSha256:crypto.createHash('sha256').update(Buffer.from(payload.proof.slice(2),'hex')).digest('hex'),quoteVersion:Buffer.from(payload.journal.slice(2),'hex').readUInt16BE(5),quoteBodyType:Buffer.from(payload.journal.slice(2),'hex').readUInt16BE(7),journalSha256:crypto.createHash('sha256').update(Buffer.from(payload.journal.slice(2),'hex')).digest('hex')},
  scope:'Locally impersonated test transactions; original node snapshot is restored after recording receipts/traces. Reverts and returned false are distinguished. These are not SDK-signed or public transactions.',
  limitations:'Negative gas depends on the explicit gas cap, especially invalid curve points/precompile failures. Call tracing does not separate refund/floor accounting. No L2 data fees.',results:[]};
const save=()=>fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n');save();
const event=cast('keccak','AttestationSubmittedV2(bool,uint8,uint16,uint16,bytes32,bool,bytes)');
async function transaction(label,calldata,{admin=false,expect='reject',gas=2000000}={}) {
  const hash=await rpc('eth_sendTransaction',[{from:admin?owner:actor,to:fee,data:calldata,gas:'0x'+gas.toString(16),gasPrice:'0x3b9aca00',value:admin?'0x0':'0x16345785d8a0000'}]);
  let receipt;
  for(let i=0;i<120;i++){receipt=await rpc('eth_getTransactionReceipt',[hash]);if(receipt)break;await new Promise(r=>setTimeout(r,100));}
  if(!receipt)throw new Error('Receipt unavailable');
  const trace=await rpc('debug_traceTransaction',[hash,{tracer:'callTracer'}]);
  const reverted=BigInt(receipt.status)===0n;
  let accepted=false,output=null,quoteBody=null;
  // Raw V2 returns (bool,bytes,bytes); ZK V2 returns (bool,bytes).
  const isRaw=calldata.startsWith('0xcaf3ffa9')||calldata.startsWith('0x569d0f33');
  if(!reverted && !admin){
    const returned=JSON.parse(cast('abi-decode','--json',isRaw?'f()(bool,bytes,bytes)':'f()(bool,bytes)',trace.output));
    accepted=returned[0];output=returned[1];if(isRaw)quoteBody=returned[2];
  }
  const acceptedEvents=receipt.logs.filter(log=>log.address.toLowerCase()===fee.toLowerCase() && log.topics[0]===event && BigInt('0x'+log.data.slice(2,66))!==0n).length;
  const row={label,hash,gasLimit:gas,gasUsed:Number(BigInt(receipt.gasUsed)),calldataBytes:(calldata.length-2)/2,reverted,accepted,output,quoteBody,acceptedEvents,receipt,trace};
  report.results.push(row);save();
  const unexpected=admin?reverted:
    expect==='accept'?(reverted||!accepted||acceptedEvents!==1||(isRaw&&(!quoteBody||quoteBody==='0x'))):
    (accepted||acceptedEvents!==0);
  if(unexpected)throw new Error(`${label}: unexpected acceptance/receipt`);
  console.log(`${label}: gas=${row.gasUsed} reverted=${reverted} accepted=${accepted}`);
}
const raw=(quote)=>data('verifyAndAttestOnChainV2(bytes,uint32,bool)',quote,fixture.tcbEvaluationDataNumber,false);
const zk=(journal=payload.journal,proof=payload.proof,id=payload.programId,evalNumber=fixture.tcbEvaluationDataNumber,minCheck=false)=>data('verifyAndAttestWithZKProofV2(bytes,uint8,bytes,bytes32,uint32,bool)',journal,payload.backend,proof,id,evalNumber,minCheck);
const flip=(value,index)=>{const bytes=Buffer.from(value.slice(2),'hex');bytes[index]^=1;return '0x'+bytes.toString('hex');};
let failure;
try {
  await rpc('anvil_setBalance',[actor,'0x56bc75e2d63100000']);
  await rpc('anvil_impersonateAccount',[actor]);await rpc('anvil_impersonateAccount',[owner]);
  await transaction('admin.unpause',data('setZkV2Paused(bool)',false),{admin:true,gas:100000});
  await transaction('baseline.raw',raw(fixture.quote),{expect:'accept',gas:12000000});
  await transaction('baseline.zk',zk(),{expect:'accept'});
  await transaction('raw.trailing',raw(fixture.quote+'00'),{gas:12000000});
  await transaction('raw.signature',raw(flip(fixture.quote,80)),{gas:12000000});
  await transaction('raw.truncated',raw(fixture.quote.slice(0,22)),{gas:12000000});
  await transaction('zk.proof',zk(payload.journal,flip(payload.proof,(payload.proof.length-2)/2-1)));
  await transaction('zk.journal',zk(flip(payload.journal,25)));
  await transaction('zk.output-major',zk(flip(payload.journal,1)));
  await transaction('zk.program-id',zk(payload.journal,payload.proof,flip(payload.programId,31)));
  await transaction('zk.mode-mismatch',zk(payload.journal,payload.proof,payload.programId,fixture.tcbEvaluationDataNumber,true));
  await transaction('zk.truncated',zk(payload.journal,'0x01'));
  await transaction('zk.evaluation',zk(payload.journal,payload.proof,payload.programId,4294967295));
  await transaction('admin.pause',data('setZkV2Paused(bool)',true),{admin:true,gas:100000});
  await transaction('zk.paused',zk());
  await transaction('admin.unpause-before-freeze',data('setZkV2Paused(bool)',false),{admin:true,gas:100000});
  await transaction('admin.freeze',data('freezeVerifyRoute(uint8,bytes4)',payload.backend,payload.proof.slice(0,10)),{admin:true,gas:100000});
  await transaction('zk.frozen',zk());
}catch(error){failure=error;report.error=error.message;}
finally {
  try {
    await rpc('anvil_stopImpersonatingAccount',[actor]);await rpc('anvil_stopImpersonatingAccount',[owner]);
    if(!await rpc('evm_revert',[snapshot]))throw new Error('Snapshot restoration failed');
    const after=await rpc('eth_getBlockByNumber',['latest',false]);
    if(after.hash!==before.hash)throw new Error('Fork snapshot readback mismatch');
    report.snapshotRestored=true;
  }catch(error){failure??=error;report.cleanupError=error.message;}
  report.status=failure?'FAILED':'PASS';save();
}
if(failure)throw failure;
console.log('Negative receipts/traces recorded; test-only transactions removed by local snapshot restoration.');
