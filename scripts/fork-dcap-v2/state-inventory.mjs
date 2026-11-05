#!/usr/bin/env node
// Read-only source material for a release manifest, not deployment approval.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
const [chain, endpoint, block, output] = process.argv.slice(2);
if (!output || fs.existsSync(output)) throw new Error('Usage: state-inventory.mjs CHAIN PUBLIC_RPC PINNED_BLOCK NEW_REPORT.json');
const url=new URL(endpoint);
if(url.username || url.password || url.search) throw new Error('Use a public endpoint; do not persist RPC credentials');
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const contracts=JSON.parse(fs.readFileSync(path.join(root,`rust-crates/libraries/network-registry/deployment/current/${chain}/dcap.json`)));
const cast=(...args)=>execFileSync('cast',args,{encoding:'utf8',maxBuffer:4*1024*1024}).trim();
const at='0x'+BigInt(block).toString(16);
const result={schema:1,status:'IN_PROGRESS',chainId:Number(chain),rpc:endpoint,block:Number(block),
  scope:'Observed addresses/code hashes/owners, evaluation 17–21 and Fee/Router event history. Storage authorizations, universal-verifier route histories and final release decisions still require review.',errors:[],contracts:{},router:{},backends:{}};
const save=()=>fs.writeFileSync(output,JSON.stringify(result,null,2)+'\n');
async function rpc(method,params=[]) {
  if(!['eth_chainId','eth_getBlockByNumber','eth_getCode','eth_call','eth_getLogs'].includes(method)) throw new Error('Read-only RPC only');
  const res=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(30000)});
  if(!res.ok) throw new Error(`HTTP ${res.status}`);
  const body=await res.json(); if(body.error) throw new Error(JSON.stringify(body.error));
  if(body.result===undefined) throw new Error('Missing result'); return body.result;
}
if(BigInt(await rpc('eth_chainId'))!==BigInt(chain)) throw new Error('Wrong chain');
const pin=await rpc('eth_getBlockByNumber',[at,false]);
if(!pin?.hash) throw new Error('Pinned block unavailable');
result.blockHash=pin.hash;result.timestamp=Number(BigInt(pin.timestamp));save();
async function read(label,fn) {try{return await fn();}catch(error){result.errors.push({label,error:error.message});return null;}finally{save();}}
async function call(to,sig,returns,...args) {
  const data=cast('calldata',sig,...args.map(String));
  const bytes=await rpc('eth_call',[{to,data},at]);
  return JSON.parse(cast('abi-decode','--json',`f()(${returns})`,bytes))[0];
}
async function contract(label,address,owned=false) {
  if(!address || BigInt(address)===0n) return;
  const code=await read(`${label}.code`,()=>rpc('eth_getCode',[address,at]));
  result.contracts[label]={address,codeBytes:code===null?null:(code.length-2)/2,codeHash:code===null?null:cast('keccak',code)};
  if(owned) result.contracts[label].owner=await read(`${label}.owner`,()=>call(address,'owner()','address'));
}
const fee=contracts.AutomataDcapAttestationFee,router=contracts.PCCSRouter;
await contract('legacyFee',fee,true);await contract('router',router,true);
result.feeBasisPoints=await read('fee.bp',()=>call(fee,'getBp()','uint16'));
for(const name of ['tcbEvalDaoAddr','pcsDaoAddr','pckDaoAddr','pckHelperAddr','crlHelperAddr','fmspcTcbHelperAddr']) {
  const address=await read(`router.${name}`,()=>call(router,`${name}()`,'address'));
  result.router[name]=address;await contract(name,address,name==='tcbEvalDaoAddr');
}
result.dependencyConfigs={};
for(const name of ['pcsDaoAddr','pckDaoAddr']) {
  const address=result.router[name];if(!address) continue;
  result.contracts[name].ownership='No owner() on these DAO implementations; inspect resolver and dependency config';
  const resolver=await read(`${name}.resolver`,()=>call(address,'resolver()','address'));
  await contract(`${name}.resolver`,resolver,true);
  const config=await read(`${name}.dependencyConfig`,()=>call(address,'dependencyConfig()','address'));
  if(config && BigInt(config)!==0n && !result.dependencyConfigs[config]) {
    await contract(`dependencyConfig.${config}`,config,true);
    const row=result.dependencyConfigs[config]={};
    for(const field of ['pcsDao','crlHelper','pendingPcsDao','pendingCrlHelper']) row[field]=await read(`dependencyConfig.${field}`,()=>call(config,`${field}()`,'address'));
    row.pendingExecutableAt=await read('dependencyConfig.pendingExecutableAt',()=>call(config,'pendingExecutableAt()','uint64'));
  }
}
result.defaultEvaluations={};
for(const tee of [0,1]) result.defaultEvaluations[tee]=await read(`standardEvaluation.${tee}`,()=>call(router,'getStandardTcbEvaluationDataNumber(uint8)','uint32',tee));
if(result.router.pcsDaoAddr) {
  const p256=await read('P256',()=>call(result.router.pcsDaoAddr,'P256_VERIFIER()','address'));
  await contract('P256',p256); // Zero bytecode may be a precompile, not a missing contract.
}
result.evaluations={};
for(const evalNumber of [17,18,19,20,21]) {
  const row=result.evaluations[evalNumber]={};
  for(const name of ['qeIdDaoVersionedAddr','fmspcTcbDaoVersionedAddr']) {
    const address=await read(`${name}.${evalNumber}`,()=>call(router,`${name}(uint32)`,'address',evalNumber));
    row[name]=address;await contract(`${name}.${evalNumber}`,address,true);
    if(address && BigInt(address)!==0n) {
      const resolver=await read(`${name}.${evalNumber}.resolver`,()=>call(address,'resolver()','address'));
      row[`${name}.resolver`]=resolver;await contract(`resolver.${name}.${evalNumber}`,resolver,true);
    }
  }
}
for(const version of [3,4,5]) {
  const address=await read(`quoteVerifier.${version}`,()=>call(fee,'quoteVerifiers(uint16)','address',version));
  await contract(`quoteVerifier.${version}`,address);
}
for(const [name,kind] of [['risc0',1],['sp1',2]]) {
  const row=result.backends[name]={};
  row.universalVerifier=await read(`${name}.verifier`,()=>call(fee,'zkVerifier(uint8)','address',kind));
  row.defaultProgramId=await read(`${name}.id`,()=>call(fee,'programIdentifier(uint8)','bytes32',kind));
  row.programIds=await read(`${name}.ids`,()=>call(fee,'programIdentifiers(uint8)','bytes32[]',kind));
  await contract(`${name}.universalVerifier`,row.universalVerifier);
}
const events={
  fee:['ZkRouteAdded(uint8,bytes4,address)','ZkRouteFrozen(uint8,bytes4)'],
  router:['SetCallerAuthorization(address,bool)','UpdateCallerRestriction(bool)',
    'UpdateConfig(address,address,address,address,address,address)',
    'UpdateQeIdDaoVersionedAddr(uint32,address)','UpdateFmspcTcbDaoVersionedAddr(uint32,address)'],
};
result.eventHistory={};
for(const [name,signatures] of Object.entries(events)) {
  const topics=Object.fromEntries(signatures.map(sig=>[cast('keccak',sig),sig]));
  const logs=await read(`${name}.genesisToPinEvents`,()=>rpc('eth_getLogs',[{address:name==='fee'?fee:router,fromBlock:'0x0',toBlock:at,topics:[Object.keys(topics)]}]));
  result.eventHistory[name]={fromBlock:0,toBlock:Number(block),complete:logs!==null,topics,logs};
}
const confirm=await rpc('eth_getBlockByNumber',[at,false]);
if(confirm?.hash!==pin.hash) throw new Error('Pinned block changed during reads');
result.status=result.errors.length?'PARTIAL':'OBSERVED_FIELDS_PASS_REVIEW_REQUIRED';save();
console.log(`${chain}: ${result.status}; ${Object.keys(result.contracts).length} contracts; errors=${result.errors.length}`);
