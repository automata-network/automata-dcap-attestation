#!/usr/bin/env node
// Read-only verification of the local isolated V2 deployment, not production release approval.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const [deploymentFile,output]=process.argv.slice(2);
if(!output || fs.existsSync(output))throw new Error('Usage: manifest-readback.mjs LOCAL_DEPLOYMENT NEW_MANIFEST.json');
const d=JSON.parse(fs.readFileSync(deploymentFile)),endpoint=new URL(d.rpc);
if(d.status!=='DEPLOYMENT_AND_COLLATERAL_TRANSACTIONS_PASS' || endpoint.protocol!=='http:' || endpoint.hostname!=='127.0.0.1' || endpoint.username || endpoint.password)throw new Error('Local completed deployment only');
const cast=(...args)=>execFileSync('cast',args,{encoding:'utf8',maxBuffer:4*1024*1024}).trim();
async function rpc(method,params=[]) {
  if(!['anvil_nodeInfo','eth_getBlockByNumber','eth_getCode','eth_getStorageAt','eth_call'].includes(method))throw new Error('Read-only methods only');
  // Archive cache misses can take longer than a warm SDK call. Retry only
  // transport timeouts; never turn a contract/RPC error into a passing field.
  for(let attempt=0;attempt<3;attempt++) {
    try {
      const r=await fetch(endpoint,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(30000)});
      const b=await r.json();if(b.error)throw new Error(JSON.stringify(b.error));return b.result;
    }catch(error){if(error.name!=='TimeoutError' || attempt===2)throw new Error(`${method}: ${error.message}`);}
  }
}
const info=await rpc('anvil_nodeInfo'),block=await rpc('eth_getBlockByNumber',['latest',false]);
if(info.environment?.chainId!==11155111 || info.forkConfig?.forkBlockNumber!==11689923 || info.hardFork!=='Osaka' || (info.network && info.network!=='ethereum') || d.origin.currentBlockHash!=='0x4ee0fcdc5b220406b457d0242cc280f0313ff1cc72bd5d9fdf041808881c8096')throw new Error('Wrong fork/runtime');
const at=block.number;
const call=async(to,sig,returns,...args)=>JSON.parse(cast('abi-decode','--json',`f()(${returns})`,await rpc('eth_call',[{to,data:cast('calldata',sig,...args.map(String))},at])))[0];
const same=(a,b)=>String(a).toLowerCase()===String(b).toLowerCase();
const word=x=>BigInt(x).toString(16).padStart(64,'0');
const v2=d.contracts.AutomataDcapAttestationV2.address,router=d.contracts.PCCSRouter.address,helper=d.contracts.PCKHelper.address;
const legacyRouter=d.legacy.PCCSRouter,legacy=d.legacy.AutomataDcapAttestationFee;
const p256=await call(d.originalRouter.pcsDaoAddr,'P256_VERIFIER()','address');
const manifest={schema:1,status:'IN_PROGRESS',scope:'Sepolia local fork readback of the isolated V2 stack only; no release approval or current registry promotion',origin:d.origin,readbackBlock:{number:at,hash:block.hash},
  source:{dcapHead:execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).trim(),pccsHead:execFileSync('git',['-C','evm/lib/automata-on-chain-pccs','rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).trim(),
    finalReleaseCommitFrozen:false,hostLockSha256:crypto.createHash('sha256').update(fs.readFileSync(path.join(root,'rust-crates/Cargo.lock'))).digest('hex')},contracts:{},router:{address:router},legacyRouter:{address:legacyRouter},backends:{},errors:[]};
const save=()=>fs.writeFileSync(output,JSON.stringify(manifest,null,2)+'\n');save();
try {
  for(const [name,c] of Object.entries(d.contracts)) {
    const a=JSON.parse(fs.readFileSync(path.join(root,`evm/out_fork_osaka/${name}.sol/${name}.json`)));
    if(a.metadata.settings.evmVersion!=='paris')throw new Error('Non-release bytecode target');
    const code=await rpc('eth_getCode',[c.address,at]);
    const actual=Buffer.from(code.slice(2),'hex'),expected=Buffer.from(a.deployedBytecode.object.replace(/^0x/,''),'hex');
    if(actual.length!==expected.length || actual.length>24576 || actual.length===0)throw new Error(name+': invalid runtime size');
    const observed=[];
    for(const refs of Object.values(a.deployedBytecode.immutableReferences || {})) {
      const values=new Set(refs.map(r=>actual.subarray(r.start,r.start+r.length).toString('hex')));
      if(values.size!==1)throw new Error('Inconsistent immutable references');
      observed.push([...values][0]);
      for(const r of refs){actual.fill(0,r.start,r.start+r.length);expected.fill(0,r.start,r.start+r.length);}
    }
    if(!actual.equals(expected))throw new Error(name+': runtime differs outside immutable slots');
    const row={address:c.address,codeBytes:actual.length,codeHash:cast('keccak',code),artifactMatch:'PASS',compiler:a.metadata.compiler.version,evmTarget:a.metadata.settings.evmVersion};
    if(/^V[345]QuoteVerifier$/.test(name)) {
      const version=Number(name[1]);
      if(JSON.stringify([...observed].sort())!==JSON.stringify([word(router),word(p256),word(version)].sort()))throw new Error('Unreviewed immutable values');
      row.router=await call(c.address,'pccsRouter()','address');row.quoteVersion=Number(await call(c.address,'quoteVersion()','uint16'));row.p256=await call(c.address,'P256_VERIFIER()','address');
      if(!same(row.router,router)||!same(row.p256,p256)||row.quoteVersion!==version||!same(await call(v2,'quoteVerifiers(uint16)','address',version),c.address))throw new Error('Constructor/registration mismatch');
    } else if(observed.length)throw new Error('Unexpected immutables');
    manifest.contracts[name]=row;
  }
  // The isolated Router is the same PCCSRouter artifact as the shared one; its
  // live runtime hash must match the untouched legacy Router runtime.
  const routerCode=await rpc('eth_getCode',[router,at]),legacyRouterCode=await rpc('eth_getCode',[legacyRouter,at]);
  manifest.router.codeHash=cast('keccak',routerCode);
  if(manifest.router.codeHash!==cast('keccak',legacyRouterCode))throw new Error('Isolated Router runtime differs from the shared Router artifact');
  // Router packs caller restriction in slot 1 byte 0, followed by tcbEvalDao.
  // Validate both before decoding its authorization mapping in slot 0.
  const packed=BigInt(await rpc('eth_getStorageAt',[router,'0x1',at]));
  const tcbEvalDao=await call(router,'tcbEvalDaoAddr()','address');
  if(((packed>>8n)&((1n<<160n)-1n))!==BigInt(tcbEvalDao))throw new Error('Router layout mismatch');
  if((packed&255n)!==1n)throw new Error('Caller restriction must be enabled on the isolated Router');
  manifest.router.callerRestriction=true;
  manifest.owner=await call(v2,'owner()','address');manifest.router.owner=await call(router,'owner()','address');
  if(!same(manifest.owner,d.owner)||!same(manifest.router.owner,d.owner))throw new Error('Owner mismatch');
  manifest.feeBasisPoints=Number(await call(v2,'getBp()','uint16'));
  if(manifest.feeBasisPoints!==Number(await call(legacy,'getBp()','uint16')))throw new Error('Fee migration mismatch');
  manifest.zkV2Paused=await call(v2,'zkV2Paused()','bool');
  if(!manifest.zkV2Paused)throw new Error('V2 must remain paused pending final gates');
  // The isolated Router points at the five shared dependencies plus the new
  // helper; the legacy Router must still point at its original helper.
  const keys=['tcbEvalDaoAddr','pcsDaoAddr','pckDaoAddr','pckHelperAddr','crlHelperAddr','fmspcTcbHelperAddr'];
  for(const key of keys) {
    const value=await call(router,key+'()','address');
    const expected=key==='pckHelperAddr'?helper:d.originalRouter[key];
    if(!same(value,expected))throw new Error('Isolated Router dependency mismatch');
    manifest.router[key]=value;
    const legacyValue=await call(legacyRouter,key+'()','address');
    if(!same(legacyValue,d.originalRouter[key]))throw new Error('Legacy Router was reconfigured');
    manifest.legacyRouter[key]=legacyValue;
  }
  manifest.router.authorizedNewReaders={};
  for(const [name,c] of Object.entries(d.contracts).filter(([name])=>name!=='PCKHelper')) {
    const slot=cast('keccak',cast('abi-encode','f(address,uint256)',c.address,'0'));
    const enabled=BigInt(await rpc('eth_getStorageAt',[router,slot,at]))===1n;
    if(!enabled)throw new Error('New reader unauthorized');manifest.router.authorizedNewReaders[name]={address:c.address,enabled};
  }
  manifest.router.versionedDAOs={};
  manifest.legacyRouter.versionedDAOs={};
  for(const evaluation of [17,18,19,20,21]) {
    const row={};for(const name of ['qeIdDaoVersionedAddr','fmspcTcbDaoVersionedAddr'])row[name]=await call(router,name+'(uint32)','address',evaluation);
    const legacyRow={};for(const name of ['qeIdDaoVersionedAddr','fmspcTcbDaoVersionedAddr'])legacyRow[name]=await call(legacyRouter,name+'(uint32)','address',evaluation);
    if(JSON.stringify(row)!==JSON.stringify(legacyRow))throw new Error('Versioned DAO clone mismatch');
    manifest.router.versionedDAOs[evaluation]=row;
  }
  manifest.readers={};
  for(const [index,r] of (d.readers??[]).entries()) {
    if(!(await call(r.resolver,'isAuthorizedCaller(address)','bool',router)))throw new Error('Shared resolver missing reader grant');
    manifest.readers[index]={resolver:r.resolver,daos:r.daos};
  }
  for(const [name,kind] of [['risc0',1],['sp1',2]]) {
    const configured=d.programs?.[name];
    const universal=await call(v2,'zkVerifierV2(uint8)','address',kind);
    const strictId=await call(v2,'programIdentifierV2(uint8)','bytes32',kind);
    const ids=await call(v2,'programIdentifiersV2(uint8)','bytes32[]',kind);
    const oldIds=await call(legacy,'programIdentifiers(uint8)','bytes32[]',kind),oldDefault=await call(legacy,'programIdentifier(uint8)','bytes32',kind);
    manifest.backends[name]={universalVerifier:universal,v2ProgramIds:ids,v2DefaultProgramId:strictId,
      legacyProgramIds:oldIds,legacyDefaultProgramId:oldDefault,universalReusedUnchanged:configured?same(universal,configured.verifier):same(universal,await call(legacy,'zkVerifier(uint8)','address',kind))};
    if(configured) {
      if(!same(universal,configured.verifier))throw new Error('V2 verifier mismatch');
      if(configured.strictId) {
        if(!same(strictId,configured.strictId))throw new Error('Strict default mismatch');
        const [registered,minCheck]=await call(v2,'programModeV2(uint8,bytes32)','bool,bool',kind,configured.strictId);
        if(!registered||minCheck)throw new Error('Strict program mode mismatch');
      } else if(BigInt(strictId)!==0n)throw new Error('Unexpected strict default');
      if(configured.minimalId) {
        const [registered,minCheck]=await call(v2,'programModeV2(uint8,bytes32)','bool,bool',kind,configured.minimalId);
        if(!registered||!minCheck)throw new Error('Minimal program mode mismatch');
      }
      if(ids.length!==Number(Boolean(configured.strictId))+Number(Boolean(configured.minimalId)))throw new Error('Unreviewed V2 program IDs');
    } else {
      if(ids.length!==0 || BigInt(strictId)!==0n || BigInt(universal)===0n)throw new Error('Unexpected V2 ZK configuration');
    }
    // Historical inline-body IDs must never be migrated into the compact V2 registry.
    for(const id of oldIds) {
      const [registered]=await call(v2,'programModeV2(uint8,bytes32)','bool,bool',kind,id);
      if(registered)throw new Error('Historical program migrated into compact V2');
    }
  }
  const picoIds=await call(v2,'programIdentifiersV2(uint8)','bytes32[]',3),picoId=await call(v2,'programIdentifierV2(uint8)','bytes32',3);
  if(picoIds.length || BigInt(picoId)!==0n)throw new Error('Unexpected Pico expansion');
  manifest.backends.pico={status:'N/A_LOCAL_ONLY',v2ProgramIds:[],v2DefaultProgramId:picoId};
  if((await rpc('eth_getBlockByNumber',['latest',false])).hash!==block.hash)throw new Error('Concurrent local writes during manifest readback');
  manifest.status='FORK_CONFIG_AND_RUNTIME_READBACK_PASS_NOT_RELEASE_APPROVAL';save();
  console.log('Six deployed runtimes, immutables, ownership, four readers, isolated Router, fees and V2 program modes verified; V2 remains paused.');
}catch(error){manifest.status='FAILED';manifest.errors.push(error.message);save();throw error;}
