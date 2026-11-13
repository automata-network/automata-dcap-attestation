import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {readSp1Routes, readReplacementState, verifyReplacement, validateReplacement, frozenRoute, digest, sp1Provenance} from './replacement.mjs';
import {deploymentContracts} from './deploy.mjs';
import {createReadbackRpc, createRpcRequest, executableRuntime, makeDocuments, readLegacy} from './publish-v2.mjs';

const a = n => '0x' + n.toString(16).padStart(40, '0');
const id = n => '0x' + n.toString(16).padStart(64, '0');
const selector = '0x4388a21c';
function fixture() {
  const reusedContracts = {PCCSRouterV2:a(2), PCKHelperV2:a(3), V3QuoteVerifierV2:a(4), V4QuoteVerifierV2:a(5), V5QuoteVerifierV2:a(6)};
  const p = {mode:'replace-entrypoint',chainId:560048,owner:a(8),legacyFee:a(1),legacyRouter:a(2),reusedContracts,
    contracts:{...reusedContracts,AutomataDcapAttestationV2:a(9)},sourceDeploymentTx:id(123),
    sourceSp1Provenance:[{backend:2,id:id(10),minCheck:false,buildSourceCommit:'a'.repeat(40)}],
    programs:[false,true].map((minCheck,i)=>({backend:1,id:id(20+i),minCheck,verifier:a(30),proofSelector:'0xe71e6620'}))};
  const sp1Ids = [10,11,12,13,14,15].map(id);
  const legacy = {feeBp:'123', verifiers:{3:a(4),4:a(5),5:a(6)},router:{tcbEvalDaoAddr:a(40),pcsDaoAddr:a(41),pckDaoAddr:a(42),pckHelperAddr:a(3)},
    evaluations:{21:{qeIdDaoVersionedAddr:a(43),fmspcTcbDaoVersionedAddr:a(44)}},
    backends:{2:{ids:sp1Ids,defaultId:id(12),verifier:a(31),code:'0x6001'}}};
  const events = [{backend:2,selector,verifier:a(31)}, {backend:2,selector:'0x11111111',verifier:a(32)},
    {backend:2,selector:'0x22222222',verifier:a(33)}, {backend:2,selector:'0x22222222',frozen:true}];
  const routes = new Map([[selector,a(31)],['0x11111111',a(32)],['0x22222222',frozenRoute]]);
  const rpc = {
    receipt: async ()=>({status:'0x1',contractAddress:a(1),blockNumber:'0x100'}),
    routeEvents:async()=>events,
    route:async(to,backend,s)=> backend===1 ? (s==='0xe71e6620'?a(30):a(0)) : routes.get(s) ?? a(31),
    code:async()=> '0x6000', verifyArtifact:async()=>{},verifyRouterLayout:async()=>{},storage:async()=> '0x1',authorized:async()=>true,
    call:async(to,sig,ret,...args)=>{
      if(sig==='zkV2Paused()') return false;
      if(sig==='owner()') return a(8);
      if(sig==='getBp()') return '123';
      if(sig==='resolver()') return a(50);
      if(sig==='isAuthorizedCaller(address)') return true;
      if(sig==='VERIFIER_HASH()') return selector+'0'.repeat(56);
      if(sig==='quoteVerifiers(uint16)') return legacy.verifiers[args[0]];
      if(sig==='programModeV2(uint8,bytes32)') return [true,BigInt(args[1])%2n===1n];
      if(sig==='programIdentifiersV2(uint8)') return args[0]===1?[id(20),id(21)]:args[0]===2?sp1Ids:[];
      if(sig==='programIdentifierV2(uint8)') return args[0]===1?id(20):args[0]===2?id(12):id(0);
      if(sig==='zkVerifierV2(uint8)') return args[0]===1?a(30):args[0]===2?a(31):a(0);
      throw Error(`Unexpected ${sig}`);
    }
  };
  return {p,legacy,rpc,events,routes};
}

test('replacement permits only one CREATE and reuses five exact addresses',()=>{
  const {p}=fixture();const tx={transactionType:'CREATE',contractName:'AutomataDcapAttestationV2',contractAddress:a(9)};
  assert.deepEqual(deploymentContracts([tx],p.reusedContracts),p.contracts);
  for(const txs of [[],[tx,tx],[{...tx,contractName:'PCCSRouter'}]]) assert.throws(()=>deploymentContracts(txs,p.reusedContracts));
});
test('original provenance is preserved; no fabricated current build commit',()=>{
  const {p}=fixture();const m={plan:{chainId:p.chainId,contracts:{...p.reusedContracts,AutomataDcapAttestationV2:p.legacyFee},programs:p.sourceSp1Provenance}};
  validateReplacement(p,m);
  assert.throws(()=>validateReplacement({...p,sourceSp1Provenance:[{...p.sourceSp1Provenance[0],buildSourceCommit:'b'.repeat(40)}]},m),/provenance/);
  assert.throws(()=>validateReplacement({...p,deploySp1Groth16V6:true},m),/reuse/);
  assert.throws(()=>validateReplacement({...p,programs:p.programs.slice(0,1)},m),/strict and minimal/);
});
test('route history retains nondefault verifiers and permanent freezes, with readback',async()=>{
  const {p,rpc,events}=fixture();events.push({backend:1,selector:'0x73c457ba',verifier:a(98)});
  const routes=await readSp1Routes(p,rpc);
  assert.equal(routes.length,3);assert.equal(routes.find(x=>x.selector==='0x22222222').verifier,frozenRoute);
  await assert.rejects(readSp1Routes(p,{...rpc,route:async()=>a(99)}),/readback mismatch/);
  await assert.rejects(readSp1Routes(p,{...rpc,receipt:async()=>({status:'0x1',contractAddress:a(99)})}),/deployment receipt/);
  events.push({backend:2,selector:'0x22222222',verifier:a(99)});
  await assert.rejects(readSp1Routes(p,rpc),/permanent freeze/);
});
test('six live SP1 IDs and non-first strict default survive stale two-ID registry',async()=>{
  const {p,legacy,rpc}=fixture();const migration=await readReplacementState(p,legacy,rpc);
  assert.equal(migration.sp1.programs.length,6);assert.equal(migration.sp1.defaultId,id(12));
  assert.deepEqual(migration.sp1.programs[0].buildProvenance,p.sourceSp1Provenance[0]);
  assert.equal(migration.sp1.programs[2].buildProvenance,null);
  assert.equal(migration.runtimeSha256.PCKHelperV2,digest(Buffer.from('6000','hex')));
  const before={...legacy,migration};await verifyReplacement(p,before,rpc);
  await assert.rejects(verifyReplacement(p,before,{...rpc,authorized:async()=>false}),/authorization/);
  await assert.rejects(verifyReplacement(p,before,{...rpc,route:async(to,b,s)=>s==='0x22222222'?a(31):rpc.route(to,b,s)}),/freeze/);
  await assert.rejects(verifyReplacement(p,before,{...rpc,route:async(to,b,s)=>b===1&&s==='0x73c457ba'?a(30):rpc.route(to,b,s)}),/Unapproved/);
  await assert.rejects(verifyReplacement(p,before,{...rpc,code:async()=> '0x6001'}),/runtime changed/);
  await assert.rejects(verifyReplacement(p,before,{...rpc,call:async(to,sig,ret,...args)=>
    sig==='programIdentifiersV2(uint8)'&&args[0]===2?[id(10),id(11)]:rpc.call(to,sig,ret,...args)}),/inventory/);
});
test('source pause, missing reader permission or incompatible mode abort migration',async()=>{
  for(const sig of ['zkV2Paused()','isAuthorizedCaller(address)','programModeV2(uint8,bytes32)']) {
    const {p,legacy,rpc}=fixture();
    await assert.rejects(readReplacementState(p,legacy,{...rpc,call:async(to,s,ret,...args)=>s===sig
      ? (s==='zkV2Paused()'?true:s==='isAuthorizedCaller(address)'?false:[false,false]):rpc.call(to,s,ret,...args)}));
  }
});
test('frozen-route decoder never hides unrelated RPC failures',async()=>{
  const rpc=createReadbackRpc(async()=>{throw Error('provider unavailable');},{number:'0x100'},()=> '0x1234');
  await assert.rejects(rpc.route(a(1),2,selector),/provider unavailable/);
});
test('frozen routes require the exact custom error data, not any revert',async()=>{
  const request=async()=>{throw Object.assign(Error('execution reverted'),{revertData:'0x1234'});};
  assert.equal(await createReadbackRpc(request,{number:'0x100'},()=> '0x1234').route(a(1),2,selector),frozenRoute);
  await assert.rejects(createReadbackRpc(request,{number:'0x100'},()=> '0x9999').route(a(1),2,selector),/execution reverted/);
});
test('event pagination shrinks provider-limited ranges without gaps or silent outages',async()=>{
  const completed=[];
  const rpc=createReadbackRpc(async(method,[filter])=>{
    assert.equal(method,'eth_getLogs'); const start=BigInt(filter.fromBlock),end=BigInt(filter.toBlock);
    if(end-start+1n>4n) throw Error('getLogs request exceeded max allowed range');
    completed.push([Number(start),Number(end)]);return [];
  },{number:'0xf'},()=> '0x'+'a'.repeat(64));
  assert.deepEqual(await rpc.routeEvents(a(1),'0x0'),[]);
  assert.deepEqual(completed.flatMap(([start,end])=>Array.from({length:end-start+1},(_,i)=>start+i)),Array.from({length:16},(_,i)=>i));
  await assert.rejects(createReadbackRpc(async()=>{throw Error('authentication failed');},{number:'0xf'},()=> '0x'+'a'.repeat(64)).routeEvents(a(1),'0x0'),/authentication/);
});
test('route event decoder matches Solidity ABI: backend indexed, selector in data',async()=>{
  const added=id(100),frozen=id(101),sel='0xabcdef01';
  const logs=[{address:a(1),topics:[added,id(2)],data:selector+'0'.repeat(56)+a(31).slice(2).padStart(64,'0'),blockNumber:'0x1',logIndex:'0x0'},
    {address:a(1),topics:[frozen,id(2)],data:sel+'0'.repeat(56),blockNumber:'0x1',logIndex:'0x1'}];
  const rpc=createReadbackRpc(async()=>logs,{number:'0x1'},(bin,args)=>args[1].startsWith('ZkRouteAdded')?added:frozen);
  const decoded=await rpc.routeEvents(a(1),'0x1');
  assert.deepEqual(decoded.map(x=>[x.backend,x.selector,x.verifier,x.frozen]),[[2,selector,a(31),false],[2,sel,frozenRoute,true]]);
});
test('reused runtime metadata may differ but executable instructions must match',()=>{
  // CBOR map {0: 1} and {0: 2}, each three bytes plus a two-byte footer length.
  const old='0x60016002a100010003',sameCode='0x60016002a100020003',differentCode='0x60016003a100010003';
  assert.ok(executableRuntime(old).equals(executableRuntime(sameCode)));
  assert.ok(!executableRuntime(old).equals(executableRuntime(differentCode)));
  for(const bad of ['0x','0x6000','0x60016002ffff']) assert.throws(()=>executableRuntime(bad));
});
test('replacement registry preserves old keys, records actual reused helper, and rejects extra deployments',()=>{
  const {p}=fixture();const dcap={AutomataDcapAttestationV2:p.legacyFee,AutomataDcapAttestationFee:a(90),PCKHelperV2:a(91)};
  const pccs={PCKHelper:a(92),PCKHelperV2:a(91)};
  const documents=makeDocuments(p,dcap,pccs);
  assert.equal(documents.dcap.AutomataDcapAttestationFee,a(90));assert.equal(documents.dcap.AutomataDcapAttestationV2,a(9));
  assert.equal(documents.pccs.PCKHelper,a(92));assert.equal(documents.pccs.PCKHelperV2,a(3));
  assert.equal(pccs.PCKHelperV2,a(91));
  assert.throws(()=>makeDocuments({...p,contracts:{...p.contracts,PCCSRouterV2:a(98)}},dcap,pccs),/Reused/);
});
test('optional live finalized V2 migration inventory (read-only)', {skip:!process.env.DCAP_REPLACEMENT_RPC},async()=>{
  const chain=Number(process.env.DCAP_REPLACEMENT_CHAIN);assert.ok(Number.isSafeInteger(chain));
  const manifest=JSON.parse(fs.readFileSync(new URL(`../../rust-crates/libraries/network-registry/deployment/v2.0/${chain}/manifest.json`,import.meta.url)));
  const request=createRpcRequest(process.env.DCAP_REPLACEMENT_RPC);
  assert.equal(Number(BigInt(await request('eth_chainId'))),chain);
  const block=await request('eth_getBlockByNumber',[process.env.DCAP_REPLACEMENT_BLOCK
    ? '0x'+BigInt(process.env.DCAP_REPLACEMENT_BLOCK).toString(16):'finalized',false]);
  const rpc=createReadbackRpc(request,block);const c=manifest.plan.contracts;
  const p={...manifest.plan,programs:[],mode:'replace-entrypoint',legacyFee:c.AutomataDcapAttestationV2,legacyRouter:c.PCCSRouterV2,
    sourceSp1Provenance:sp1Provenance(manifest),
    sourceDeploymentTx:manifest.transactions.find(r=>r.contractAddress?.toLowerCase()===c.AutomataDcapAttestationV2.toLowerCase()).transactionHash,
    reusedContracts:Object.fromEntries(Object.entries(c).filter(([k])=>k!=='AutomataDcapAttestationV2'))};
  p.reusedContracts.PCKHelperV2=await rpc.call(p.legacyRouter,'pckHelperAddr()','address');
  for(const v of [3,4,5]) p.reusedContracts[`V${v}QuoteVerifierV2`]=await rpc.call(p.legacyFee,'quoteVerifiers(uint16)','address',v);
  const state=await readLegacy(p,rpc);
  assert.equal(state.migration.sp1.programs.length,state.backends[2].ids.length);
  assert.ok(state.migration.sp1.programs.some(x=>x.id===state.migration.sp1.defaultId&&!x.minCheck));
  console.log(JSON.stringify({chain,block:Number(BigInt(block.number)),sp1Ids:state.migration.sp1.programs.length,
    sp1Routes:state.migration.sp1.routes,defaultId:state.migration.sp1.defaultId,
    missingBuildProvenance:state.migration.sp1.programs.filter(x=>!x.buildProvenance).length,
    helper:state.router.pckHelperAddr,routerOwner:state.routerOwner}));
});
