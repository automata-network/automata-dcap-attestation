#!/usr/bin/env node
// Decode the successfully captured event ranges; do not invent unlogged initial state.
import fs from 'node:fs';
const [input, output] = process.argv.slice(2);
if(!output || fs.existsSync(output)) throw new Error('Usage: replay-events.mjs STATE_INVENTORY NEW_REPORT.json');
const state=JSON.parse(fs.readFileSync(input));
const report={schema:1,chainId:state.chainId,block:state.block,blockHash:state.blockHash,
  status:'EVENT_REPLAY_ONLY',router:{authorizations:{},restriction:null,configuration:null,qe:{},fmspc:{}},feeRoutes:{},checks:[],limitations:[
    'Unlogged constructor state is not inferred. null means no matching event, not false/disabled.',
    'Authorization flags are replayed events, not a private-storage readback or deployed-source equivalence check.',
    'Program-family/ATKJ metadata, universal-verifier routes and storage-writer permissions are separate.'
  ]};
const word=(data,index)=>'0x'+data.slice(2+index*64,2+(index+1)*64);
const address=(data,index)=>'0x'+word(data,index).slice(-40);
const eq=(a,b)=>String(a).toLowerCase()===String(b).toLowerCase();
for(const name of ['router','fee']) {
  const history=state.eventHistory[name];
  if(!history?.complete || !Array.isArray(history.logs) || history.fromBlock!==0 || history.toBlock!==state.block) throw new Error(`${name}: complete pinned range required`);
  const seen=new Set();
  const logs=[...history.logs].sort((a,b)=>Number(BigInt(a.blockNumber)-BigInt(b.blockNumber)) || Number(BigInt(a.transactionIndex)-BigInt(b.transactionIndex)) || Number(BigInt(a.logIndex)-BigInt(b.logIndex)));
  for(const log of logs) {
    const key=`${log.transactionHash}:${log.logIndex}`;
    if(seen.has(key) || log.removed || BigInt(log.blockNumber)>BigInt(state.block)) throw new Error('Invalid/duplicate event');
    seen.add(key);
    if(!eq(log.address,state.contracts[name==='fee'?'legacyFee':'router'].address) || log.topics.length!==1) throw new Error('Unexpected emitter/indexed ABI');
    const signature=history.topics[log.topics[0]];
    if(!signature) throw new Error('Unknown event');
    const fields=signature.slice(signature.indexOf('(')+1,-1).split(',');
    if(log.data.length!==2+64*fields.length) throw new Error('Invalid static event length');
    const data=log.data;
    if(signature.startsWith('SetCallerAuthorization')) {
      const flag=BigInt(word(data,1));if(flag>1n)throw new Error('Invalid bool');
      report.router.authorizations[address(data,0)]=flag===1n;
    } else if(signature.startsWith('UpdateCallerRestriction')) {
      const flag=BigInt(word(data,0));if(flag>1n)throw new Error('Invalid bool');
      report.router.restriction=flag===1n;
    } else if(signature.startsWith('UpdateConfig')) {
      const keys=['tcbEvalDaoAddr','pcsDaoAddr','pckDaoAddr','pckHelperAddr','crlHelperAddr','fmspcTcbHelperAddr'];
      report.router.configuration=Object.fromEntries(keys.map((key,i)=>[key,address(data,i)]));
    } else if(signature.startsWith('UpdateQeIdDaoVersionedAddr') || signature.startsWith('UpdateFmspcTcbDaoVersionedAddr')) {
      const evalNumber=Number(BigInt(word(data,0)));
      if(evalNumber>0xffffffff)throw new Error('Invalid evaluation');
      report.router[signature.startsWith('UpdateQe')?'qe':'fmspc'][evalNumber]=address(data,1);
    } else if(signature.startsWith('ZkRoute')) {
      const backend=Number(BigInt(word(data,0))), selector=word(data,1).slice(0,10);
      if(backend>255 || BigInt('0x'+word(data,1).slice(10))!==0n)throw new Error('Invalid route ABI');
      report.feeRoutes[`${backend}:${selector}`]=signature.startsWith('ZkRouteFrozen')?{frozen:true}:{frozen:false,verifier:address(data,2)};
    } else throw new Error('Unhandled event');
  }
}
function check(label,actual,expected) {
  const status=actual===undefined?'MISSING_STATE_READ':eq(actual,expected)?'PASS':'MISMATCH';
  report.checks.push({label,actual,expected,status});
}
if(report.router.configuration) for(const [key,expected] of Object.entries(report.router.configuration)) check(key,state.router[key],expected);
for(const [group,field] of [['qe','qeIdDaoVersionedAddr'],['fmspc','fmspcTcbDaoVersionedAddr']]) {
  for(const [evalNumber,expected] of Object.entries(report.router[group])) check(`${field}.${evalNumber}`,state.evaluations[evalNumber]?.[field],expected);
}
fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n',{flag:'wx'});
if(report.checks.some(c=>c.status==='MISMATCH'))throw new Error('Event replay disagrees with pinned state');
console.log(`${report.chainId}: ${Object.keys(report.router.authorizations).length} observed callers, ${report.checks.length} public-state comparisons; unlogged/private state is not inferred`);
