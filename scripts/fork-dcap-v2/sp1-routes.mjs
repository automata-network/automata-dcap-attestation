#!/usr/bin/env node
// Read-only SP1 gateway history plus every observed selector's pinned readback.
import fs from 'node:fs';
import {execFileSync} from 'node:child_process';
const [input,output]=process.argv.slice(2);
if(!output || fs.existsSync(output))throw new Error('Usage: sp1-routes.mjs STATE_INVENTORY NEW_REPORT.json');
const state=JSON.parse(fs.readFileSync(input));
const endpoint=new URL(state.rpc), gateway=state.backends?.sp1?.universalVerifier;
if(endpoint.protocol!=='https:' || endpoint.username || endpoint.password || endpoint.search)throw new Error('Public HTTPS RPC only');
if(!gateway || BigInt(gateway)===0n)throw new Error('No observed SP1 gateway; do not expand backend scope');
const cast=(...args)=>execFileSync('cast',args,{encoding:'utf8',maxBuffer:4*1024*1024}).trim();
const at='0x'+BigInt(state.block).toString(16);
const report={schema:1,chainId:state.chainId,block:state.block,blockHash:state.blockHash,gateway,status:'IN_PROGRESS',routes:{},errors:[]};
const save=()=>fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n');
async function rpc(method,params) {
  if(!['eth_chainId','eth_getBlockByNumber','eth_getLogs','eth_getCode','eth_call'].includes(method))throw new Error('Read-only RPC only');
  const res=await fetch(endpoint,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(30000)});
  if(!res.ok)throw new Error(`HTTP ${res.status}`);
  const body=await res.json();if(body.error)throw new Error(JSON.stringify(body.error));return body.result;
}
async function call(to,sig,returns,...args) {
  const data=cast('calldata',sig,...args);
  const value=await rpc('eth_call',[{to,data},at]);
  return JSON.parse(cast('abi-decode','--json',`f()(${returns})`,value));
}
save();
try {
  if(BigInt(await rpc('eth_chainId',[]))!==BigInt(state.chainId))throw new Error('Wrong chain');
  if((await rpc('eth_getBlockByNumber',[at,false]))?.hash!==state.blockHash)throw new Error('Wrong pinned block');
  report.gatewayOwner=(await call(gateway,'owner()','address'))[0];
  const added=cast('keccak','RouteAdded(bytes4,address)'),frozen=cast('keccak','RouteFrozen(bytes4,address)');
  const logs=await rpc('eth_getLogs',[{address:gateway,fromBlock:'0x0',toBlock:at,topics:[[added,frozen]]}]);
  if(!Array.isArray(logs) || logs.length>1000)throw new Error('Unexpected event result size');
  report.history={fromBlock:0,toBlock:state.block,logs};save();
  const seen=new Set();
  logs.sort((a,b)=>Number(BigInt(a.blockNumber)-BigInt(b.blockNumber)) || Number(BigInt(a.transactionIndex)-BigInt(b.transactionIndex)) || Number(BigInt(a.logIndex)-BigInt(b.logIndex)));
  for(const log of logs) {
    const key=`${log.transactionHash}:${log.logIndex}`;
    if(seen.has(key) || log.removed || log.address.toLowerCase()!==gateway.toLowerCase() || log.topics.length!==1 || ![added,frozen].includes(log.topics[0]) || log.data.length!==130 || BigInt(log.blockNumber)>BigInt(state.block))throw new Error('Invalid route event');
    seen.add(key);
    const selector=log.data.slice(0,10),verifier='0x'+log.data.slice(-40);
    if(BigInt('0x'+log.data.slice(10,66))!==0n)throw new Error('Noncanonical bytes4');
    const previous=report.routes[selector];
    if(log.topics[0]===added) {
      if(previous)throw new Error('Route added twice');
      report.routes[selector]={verifier,frozen:false};
    } else {
      if(!previous || previous.verifier!==verifier)throw new Error('Freeze without matching addition');
      previous.frozen=true;
    }
  }
  for(const [selector,row] of Object.entries(report.routes)) {
    const [verifier,isFrozen]=await call(gateway,'routes(bytes4)','address,bool',selector);
    if(verifier.toLowerCase()!==row.verifier || isFrozen!==row.frozen)throw new Error('Route history/state mismatch');
    const code=await rpc('eth_getCode',[verifier,at]);
    if(code==='0x')throw new Error('Underlying verifier has no code');
    row.codeHash=cast('keccak',code);row.codeBytes=(code.length-2)/2;
    row.version=(await call(verifier,'VERSION()','string'))[0];
    row.verifierHash=(await call(verifier,'VERIFIER_HASH()','bytes32'))[0];
    if(!row.verifierHash.startsWith(selector))throw new Error('Underlying verifier selector mismatch');
    row.readback='PASS';save();
  }
  if((await rpc('eth_getBlockByNumber',[at,false]))?.hash!==state.blockHash)throw new Error('Pin changed');
  report.status='OBSERVED_SP1_ROUTES_RECONCILED';save();
  console.log(`${state.chainId}: ${Object.keys(report.routes).length} SP1 routes reconciled; only separately tested proof formats are accepted for release`);
}catch(error){report.status='PARTIAL';report.errors.push(error.message);save();throw error;}
