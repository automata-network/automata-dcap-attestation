#!/usr/bin/env node
// Fork-only transaction replay. Never takes a private key or a public write RPC.
// Compact V2: deploys an isolated Router/PCKHelper/AttestationV2 stack. The
// shared legacy Router is never reconfigured; the only shared-state writes are
// additive reader grants for the new Router and the fixture collateral upserts.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const [endpoint, output, profile='sepolia-osaka'] = process.argv.slice(2);
if (!output || fs.existsSync(output)) throw new Error('Usage: anvil-deploy.mjs http://127.0.0.1:PORT NEW_REPORT.json [sepolia-osaka|op-sepolia-karst|hoodi-osaka]');
const pins={
  'sepolia-osaka':{chainId:11155111,block:11689923,hash:'0x4ee0fcdc5b220406b457d0242cc280f0313ff1cc72bd5d9fdf041808881c8096',hardfork:'Osaka'},
  'op-sepolia-karst':{chainId:11155420,block:48718178,hash:'0x95b1d91f43a9f6209524114ef04d8d49ba47a82743460bce939fa10a97bbac8c',hardfork:'Karst',network:'optimism'},
  // Hoodi public RPC review (2026-09-21, chainlist -> rpc.hoodi.ethpandaops.io).
  // Anvil 1.5.1 reports Prague for chain 560048 but does not execute the
  // P-256 precompile (0x100) under Prague; Hoodi's live state (successful
  // P-256 collateral upserts, production quote verifiers) requires it, so the
  // reviewed local runtime selects Osaka explicitly, exactly like the
  // sepolia-osaka profile. Confirm Hoodi's actual execution rules before any
  // non-local claim.
  // legacy deployment at registry current/560048 has SP1 v5 verifier
  // 0x7DA83eC4af493081500Ecd36d1a72c23F8fc2abd and no RISC Zero route.
  'hoodi-osaka':{chainId:560048,block:3666000,hash:'0x507bec8bb301dc25d57e09fee024cf8a099db7e8ee318c483591fed3b738a57f',hardfork:'Osaka'},
};
const pin=pins[profile];if(!pin)throw new Error('Unreviewed fork profile');
const url = new URL(endpoint);
if (url.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(url.hostname) || url.username || url.password)
  throw new Error('Only a literal loopback HTTP Anvil endpoint is allowed');
const cast = (...args) => execFileSync('cast', args, {encoding:'utf8', maxBuffer:4*1024*1024}).trim();
const calldata = (sig, ...args) => cast('calldata', sig, ...args.map(String));
// Cast's nested tuple text parser cannot safely quote arbitrary signed JSON.
// Encode the (string,bytes) tail separately, retaining the exact JSON bytes.
const signedTupleCalldata = (signature, prefix, raw, signatureBytes) => {
  const types=[...prefix.map(()=>'uint256'),'uint256'];
  const head=cast('abi-encode',`f(${types.join(',')})`,...prefix.map(String),String(32*(prefix.length+1)));
  const tail=cast('abi-encode','f(string,bytes)',raw,signatureBytes);
  const encoded=Buffer.from(tail.slice(2),'hex'),wanted=Buffer.from(raw);
  const offset=Number(BigInt('0x'+encoded.subarray(0,32).toString('hex')));
  const length=Number(BigInt('0x'+encoded.subarray(offset,offset+32).toString('hex')));
  if(length!==wanted.length || !encoded.subarray(offset+32,offset+32+length).equals(wanted))throw new Error('Signed JSON ABI bytes changed');
  return cast('sig',signature)+head.slice(2)+tail.slice(2);
};
async function rpc(method, params=[]) {
  const response = await fetch(url, {method:'POST', headers:{'content-type':'application/json'},
    body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}), signal:AbortSignal.timeout(60000)});
  const body = await response.json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}
const info = await rpc('anvil_nodeInfo');
if (info.environment?.chainId !== pin.chainId || info.forkConfig?.forkBlockNumber !== pin.block ||
    info.currentBlockHash !== pin.hash || info.hardFork !== pin.hardfork || (pin.network && info.network!==pin.network) ||
    (!pin.network && info.network && info.network!=='ethereum'))
  throw new Error('Expected a fresh, exact reviewed fork/runtime; do not reuse mutated state');
const registry = JSON.parse(fs.readFileSync(path.join(root, `rust-crates/libraries/network-registry/deployment/current/${pin.chainId}/dcap.json`)));
const report = {schema:1, status:'IN_PROGRESS', rpc:endpoint, origin:info, profile, transactions:[], contracts:{},
  legacy:registry, readers:[], programs:{},
  isolation:'Isolated V2 stack: new PCCSRouter/PCKHelper/AttestationV2/quote verifiers. The legacy Router is never reconfigured (no setConfig/helper switch). Shared-state writes are limited to additive reader grants for the new Router on existing resolver storage and the fixture collateral upserts below.'};
const save = () => fs.writeFileSync(output, JSON.stringify(report,null,2)+'\n');
save();
const call = async (to, sig, returns, ...args) => JSON.parse(cast('abi-decode','--json',`f()(${returns})`,
  await rpc('eth_call', [{to,data:calldata(sig,...args)},'latest'])));
const legacyRouter = registry.PCCSRouter, legacy = registry.AutomataDcapAttestationFee;
const owner = (await call(legacyRouter,'owner()','address'))[0];
await rpc('anvil_impersonateAccount',[owner]);
const impersonated = new Set([owner]);
await rpc('anvil_setBalance',[owner,'0x56bc75e2d63100000']); // Local-only 100 ETH.
async function tx(label, to, data, from=owner) {
  const request = {from, data, ...(to ? {to} : {})};
  const estimate = await rpc('eth_estimateGas',[request]);
  request.gas = '0x'+((BigInt(estimate)*12n)/10n+10000n).toString(16);
  const hash = await rpc('eth_sendTransaction',[request]);
  let receipt;
  for(let attempt=0;attempt<240;attempt++) {
    receipt=await rpc('eth_getTransactionReceipt',[hash]);
    if(receipt) break;
    await new Promise(resolve=>setTimeout(resolve,250));
  }
  report.transactions.push({label, hash, estimate, receipt}); save();
  if (!receipt || BigInt(receipt.status)!==1n) throw new Error(`${label} transaction failed`);
  console.log(`${label}: gas=${BigInt(receipt.gasUsed)} tx=${hash}`);
  return receipt;
}
async function send(label,to,sig,...args) { return tx(label,to,calldata(sig,...args)); }
async function deploy(name, types='', args=[]) {
  const file = path.join(root,`evm/out_fork_osaka/${name}.sol/${name}.json`);
  const artifact = JSON.parse(fs.readFileSync(file));
  if (artifact.metadata.settings.evmVersion !== 'paris') throw new Error(`${name}: release must target Paris`);
  const runtimeBytes = (artifact.deployedBytecode.object.replace(/^0x/,'').length)/2;
  if (runtimeBytes > 24576) throw new Error(`${name} exceeds EIP-170`);
  const suffix = types ? cast('abi-encode',`f(${types})`,...args).slice(2) : '';
  const receipt = await tx(`deploy.${name}`,null,artifact.bytecode.object+suffix);
  report.contracts[name] = {address:receipt.contractAddress,runtimeBytes}; save();
  return receipt.contractAddress;
}
// Frozen compact-journal collateral-hash offsets (see docs/dcap-v2-revision-progress.md):
// fmspc bytes 10..16, six collateral hashes start at byte 61 (32 bytes each,
// TCB Info hash first, QE identity hash second). Do not use the retired
// inline-body 289-byte offsets (130/194) here.
const FMSPC_HEX=[20,32], TCB_HASH_HEX=[122,186], QE_HASH_HEX=[186,250];
try {
  const keys = ['tcbEvalDaoAddr','pcsDaoAddr','pckDaoAddr','pckHelperAddr','crlHelperAddr','fmspcTcbHelperAddr'];
  const original=[];
  for(const key of keys) original.push((await call(legacyRouter,`${key}()`,'address'))[0]);
  report.originalRouter=Object.fromEntries(keys.map((k,i)=>[k,original[i]])); report.owner=owner; save();
  const p256=(await call(original[1],'P256_VERIFIER()','address'))[0];
  // Versioned DAOs differ by chain (Sepolia 17-21, Hoodi 18-21): discover the
  // evaluations present on the reviewed legacy Router instead of hardcoding.
  const evaluations=[];
  for(let evaluation=15;evaluation<=23;evaluation++) {
    const qe=(await call(legacyRouter,'qeIdDaoVersionedAddr(uint32)','address',evaluation))[0];
    const fmspc=(await call(legacyRouter,'fmspcTcbDaoVersionedAddr(uint32)','address',evaluation))[0];
    if(BigInt(qe)!==0n||BigInt(fmspc)!==0n) {
      if(BigInt(qe)===0n||BigInt(fmspc)===0n) throw new Error(`Partial versioned DAO for evaluation ${evaluation}`);
      evaluations.push(evaluation);
    }
  }
  if(!evaluations.length) throw new Error('No versioned DAOs on the legacy Router');
  const versioned={};
  for(const evaluation of evaluations) {
    versioned[evaluation]={
      qe:(await call(legacyRouter,'qeIdDaoVersionedAddr(uint32)','address',evaluation))[0],
      fmspc:(await call(legacyRouter,'fmspcTcbDaoVersionedAddr(uint32)','address',evaluation))[0],
    };
    if(BigInt(versioned[evaluation].qe)===0n||BigInt(versioned[evaluation].fmspc)===0n)
      throw new Error(`Missing versioned DAO for evaluation ${evaluation}`);
  }
  report.versionedDAOs=versioned; save();
  // Isolated stack: nothing here mutates the shared legacy Router.
  const helper=await deploy('PCKHelper');
  const router=await deploy('PCCSRouter','address,address,address,address,address,address,address',
    [owner,original[0],original[1],original[2],helper,original[4],original[5]]);
  const attestation=await deploy('AutomataDcapAttestationV2','address',[owner]);
  const bp=(await call(legacy,'getBp()','uint16'))[0];
  await send('attestation.copyBp',attestation,'setBp(uint16)',bp);
  await send('attestation.pauseV2',attestation,'setZkV2Paused(bool)',true);
  for(const version of [3,4,5]) {
    const verifier=await deploy(`V${version}QuoteVerifier`,'address,address',[p256,router]);
    await send(`attestation.setV${version}`,attestation,'setQuoteVerifier(address)',verifier);
    await send(`router.authorizeV${version}`,router,'setAuthorized(address,bool)',verifier,true);
  }
  await send('router.authorizeAttestation',router,'setAuthorized(address,bool)',attestation,true);
  await send('router.enableCallerRestriction',router,'enableCallerRestriction()');
  for(const evaluation of evaluations) {
    await send(`router.cloneQeDao.${evaluation}`,router,'setQeIdDaoVersionedAddr(uint32,address)',evaluation,versioned[evaluation].qe);
    await send(`router.cloneFmspcDao.${evaluation}`,router,'setFmspcTcbDaoVersionedAddr(uint32,address)',evaluation,versioned[evaluation].fmspc);
  }
  // Additive reader grants: the only shared-contract writes. Never DAO/writer
  // permission; resolver owners are impersonated locally on the fork only.
  const readerDaos=[original[0],original[1],original[2],
    ...evaluations.flatMap(e=>[versioned[e].qe,versioned[e].fmspc])];
  const resolvers=new Map();
  for(const dao of readerDaos) {
    const resolver=(await call(dao,'resolver()','address'))[0];
    const key=resolver.toLowerCase();
    if(!resolvers.has(key)) resolvers.set(key,{resolver,daos:[]});
    resolvers.get(key).daos.push(dao);
  }
  for(const {resolver,daos} of resolvers.values()) {
    const authorized=(await call(resolver,'isAuthorizedCaller(address)','bool',router))[0];
    if(authorized) { report.readers.push({resolver,daos,alreadyAuthorized:true}); continue; }
    const storageOwner=(await call(resolver,'owner()','address'))[0];
    await rpc('anvil_impersonateAccount',[storageOwner]);impersonated.add(storageOwner);
    await rpc('anvil_setBalance',[storageOwner,'0x56bc75e2d63100000']);
    await tx(`reader.grant.${resolver.slice(2,10)}`,resolver,calldata('setCallerAuthorization(address,bool)',router,true),storageOwner);
    if(!(await call(resolver,'isAuthorizedCaller(address)','bool',router))[0]) throw new Error('Reader grant readback failed');
    report.readers.push({resolver,daos,owner:storageOwner});
  }
  // ZK backends: reuse only the verifier ADDRESS from the legacy deployment.
  // Compact strict/minimal program IDs must be supplied explicitly; historical
  // inline-body IDs are never silently registered as compact programs.
  const envOr=(name,fallback)=>process.env[name]??fallback;
  report.legacyZkVerifiers={
    risc0:(await call(legacy,'zkVerifier(uint8)','address',1))[0],
    sp1:(await call(legacy,'zkVerifier(uint8)','address',2))[0],
  }; save();
  // Optional independent SP1 v6 verifier: DCAP_SP1_V2_VERIFIER=deploy deploys the
  // pinned official v6.1.0 artifact from its isolated 0.8.20 compilation unit
  // (evm/out), never the shared legacy gateway and never a mutable tag.
  let deployedSp1V6Verifier=null;
  if((process.env.DCAP_SP1_V2_VERIFIER||'').toLowerCase()==='deploy') {
    const artifact=JSON.parse(fs.readFileSync(path.join(root,'evm/out/SP1Groth16VerifierV6.sol/SP1Groth16VerifierV6.json')));
    if(!artifact.metadata.compiler.version.startsWith('0.8.20')) throw new Error('SP1 v6 verifier must come from the isolated 0.8.20 unit');
    if(artifact.metadata.settings.evmVersion!=='paris') throw new Error('SP1 v6 verifier must target Paris');
    const receipt=await tx('deploy.SP1Groth16VerifierV6',null,artifact.bytecode.object);
    deployedSp1V6Verifier=receipt.contractAddress;
    report.contracts.SP1Groth16VerifierV6={address:deployedSp1V6Verifier,deployedFrom:'evm/out isolated 0.8.20 unit (official v6.1.0 source)'};save();
  }
  for(const [kind,name] of [[1,'risc0'],[2,'sp1']]) {
    const legacyUniversal=(await call(legacy,'zkVerifier(uint8)','address',kind))[0];
    const universal=name==='sp1'&&deployedSp1V6Verifier?deployedSp1V6Verifier:envOr(name==='risc0'?'DCAP_RISC0_V2_VERIFIER':'DCAP_SP1_V2_VERIFIER',legacyUniversal);
    const strictId=envOr(name==='risc0'?'DCAP_RISC0_STRICT_ID':'DCAP_SP1_STRICT_ID','');
    const minimalId=envOr(name==='risc0'?'DCAP_RISC0_MINIMAL_ID':'DCAP_SP1_MINIMAL_ID','');
    for(const id of [strictId,minimalId]) if(id && !/^0x[0-9a-fA-F]{64}$/.test(id)) throw new Error(`Invalid ${name} program ID`);
    if(!strictId && !minimalId && BigInt(legacyUniversal)===0n) continue;
    if(profile==='op-sepolia-karst')throw new Error('OP backend scope changed; review instead of enabling ZK');
    if(BigInt(universal)===0n) throw new Error('Missing V2 ZK verifier');
    await send(`attestation.setZkVerifierV2.${name}`,attestation,'setZkVerifierV2(uint8,address)',kind,universal);
    const row={verifier:universal};
    if(strictId) {
      await send(`attestation.addStrict.${name}`,attestation,'addProgramIdentifierV2(uint8,bytes32,bool)',kind,strictId,false);
      await send(`attestation.defaultStrict.${name}`,attestation,'setDefaultProgramIdentifierV2(uint8,bytes32)',kind,strictId);
      row.strictId=strictId;
    }
    if(minimalId) {
      await send(`attestation.addMinimal.${name}`,attestation,'addProgramIdentifierV2(uint8,bytes32,bool)',kind,minimalId,true);
      row.minimalId=minimalId;
    }
    report.programs[name]=row;
  }
  report.zkConfigurationScope=['sepolia-osaka','hoodi-osaka'].includes(profile)
    ?'explicit-env-or-legacy-verifier-address-only; compact program IDs never derived from historical inline-body defaults'
    :'raw-only; full-history-open';
  save();
  // The pinned Ethereum Sepolia Fee's genesis-to-pin ZkRouteAdded/ZkRouteFrozen queries
  // both returned [], as recorded in the fork report. Do not generalize this
  // no-override migration to other chains without their route inventory.
  // OP has no registered backend/ID; full historical route inventory remains
  // separate from this raw-only local rehearsal and is not claimed complete.
  // Hoodi (560048) pinned state: legacy SP1 v5 verifier present, no RISC Zero
  // route (zero address); see report.legacyZkVerifiers. Do not claim a Hoodi
  // RISC Zero route exists without an explicit reviewed verifier deployment.
  for(const fixtureName of ['ata-sgx-v3','ata-tdx-v4','v5']) {
    const fixture=JSON.parse(fs.readFileSync(path.join(root,`evm/forge-test/assets/v2/fixtures/${fixtureName}.json`)));
    const pcs=original[1];
    for(const [ca,key] of [[0,'rootCaCertificate'],[2,'platformCaCertificate'],[3,'tcbSigningCertificate']]) {
      const [cert]=await call(pcs,'getCertificateById(uint8)','bytes,bytes',ca);
      if(cert.toLowerCase()!==fixture[key].toLowerCase()) await send(`${fixtureName}.pcs.cert.${ca}`,pcs,'upsertPcsCertificates(uint8,bytes)',ca,fixture[key]);
    }
    for(const [ca,key] of [[0,'rootCaCrl'],[2,'pckCrl']]) {
      const [,crl]=await call(pcs,'getCertificateById(uint8)','bytes,bytes',ca);
      if(crl.toLowerCase()!==fixture[key].toLowerCase()) {
        if(ca===0) await send(`${fixtureName}.pcs.rootCrl`,pcs,'upsertRootCACrl(bytes)',fixture[key]);
        else await send(`${fixtureName}.pcs.pckCrl`,pcs,'upsertPckCrl(uint8,bytes)',ca,fixture[key]);
      }
    }
    const expected=fixture.expectedJournal.slice(2);
    if(!evaluations.includes(Number(fixture.tcbEvaluationDataNumber))) throw new Error(`Fixture ${fixtureName} needs versioned DAO evaluation ${fixture.tcbEvaluationDataNumber}, absent on this chain`);
    const fmspc='0x'+expected.slice(...FMSPC_HEX), tcbType=fixtureName==='ata-sgx-v3'?0:1;
    const dao=(await call(legacyRouter,'fmspcTcbDaoVersionedAddr(uint32)','address',fixture.tcbEvaluationDataNumber))[0];
    const key=(await call(dao,'FMSPC_TCB_KEY(uint8,bytes6,uint32)','bytes32',tcbType,fmspc,3))[0];
    const hash=(await call(dao,'getTcbInfoContentHash(bytes32)','bytes32',key))[0];
    const validNow=async (target, collateralKey)=> {
      const [issued,expires]=await call(target,'getCollateralValidity(bytes32)','uint64,uint64',collateralKey);
      const block=await rpc('eth_getBlockByNumber',['latest',false]);
      const timestamp=BigInt(block.timestamp);
      return BigInt(issued)!==0n && BigInt(issued)<=timestamp && timestamp<=BigInt(expires);
    };
    if(hash.toLowerCase()!=='0x'+expected.slice(...TCB_HASH_HEX) || !await validNow(dao,key)) {
      const plan=JSON.parse(fs.readFileSync(path.join(root,`evm/forge-test/assets/v2/local-fork/${fmspc.slice(2)}-${tcbType}.json`)));
      const signed=JSON.parse(fixture.tcbInfoJson);
      if(JSON.stringify(signed.tcbInfo)!==plan.raw) throw new Error('Async plan/raw mismatch');
      const daoOwner=(await call(dao,'owner()','address'))[0];
      await rpc('anvil_impersonateAccount',[daoOwner]);impersonated.add(daoOwner);
      await rpc('anvil_setBalance',[daoOwner,'0x56bc75e2d63100000']);
      const role=(await call(dao,'ATTESTER_ROLE()','uint256'))[0];
      await tx(`${fixtureName}.grantAttester`,dao,calldata('grantRoles(address,uint256)',owner,role),daoOwner);
      const ref=cast('keccak',plan.raw);
      await send(`${fixtureName}.async.start`,dao,'startAsyncUpsert(bytes32,bytes,uint32)',ref,'0x'+signed.signature.replace(/^0x/,''),plan.rawLength);
      await send(`${fixtureName}.async.basic`,dao,'uploadBasicInfo(bytes32,bytes,bytes)',ref,plan.basicPayload,plan.topLevelOrder);
      for(const [group,method] of [['levels','uploadTcbLevelsBatch'],['identities','uploadTdxModuleIdentitiesBatch']]) for(const batch of plan[group])
        await send(`${fixtureName}.async.${group}.${batch.start}`,dao,`${method}(bytes32,uint256,uint256,bytes)`,ref,batch.start,batch.count,batch.payload);
      const storage=(await call(dao,'resolver()','address'))[0];
      const previous=(await call(storage,'collateralPointer(bytes32)','bytes32',key))[0];
      await send(`${fixtureName}.async.finalize`,dao,'finalizeAsyncUpsert(bytes32,bytes32)',previous,ref);
      if((await call(dao,'getTcbInfoContentHash(bytes32)','bytes32',key))[0].toLowerCase()!=='0x'+expected.slice(...TCB_HASH_HEX)) throw new Error('Async hash mismatch');
    }
    if(!await validNow(dao,key)) throw new Error('FMSPC collateral not valid at the actual block timestamp');
    const qe=(await call(legacyRouter,'qeIdDaoVersionedAddr(uint32)','address',fixture.tcbEvaluationDataNumber))[0];
    const qeKey=(await call(qe,'ENCLAVE_ID_KEY(uint256,uint256)','bytes32',tcbType===0?0:2,4))[0];
    if((await call(qe,'getIdentityContentHash(bytes32)','bytes32',qeKey))[0].toLowerCase()!=='0x'+expected.slice(...QE_HASH_HEX) || !await validNow(qe,qeKey)) {
      const qeOwner=(await call(qe,'owner()','address'))[0];
      await rpc('anvil_impersonateAccount',[qeOwner]);impersonated.add(qeOwner);
      await rpc('anvil_setBalance',[qeOwner,'0x56bc75e2d63100000']);
      const role=(await call(qe,'ATTESTER_ROLE()','uint256'))[0];
      await tx(`${fixtureName}.qe.grantAttester`,qe,calldata('grantRoles(address,uint256)',owner,role),qeOwner);
      const identity=JSON.parse(fixture.qeIdentityJson);
      await tx(`${fixtureName}.qe.upsert`,qe,signedTupleCalldata('upsertEnclaveIdentity(uint256,uint256,(string,bytes))',[tcbType===0?0:2,4],
        JSON.stringify(identity.enclaveIdentity),'0x'+identity.signature.replace(/^0x/,'')));
    }
    if((await call(qe,'getIdentityContentHash(bytes32)','bytes32',qeKey))[0].toLowerCase()!=='0x'+expected.slice(...QE_HASH_HEX) || !await validNow(qe,qeKey)) throw new Error('QE upsert hash/validity mismatch');
  }
  for(const [kind,name] of [[0,'sgx'],[1,'tdx']]) {
    const key=(await call(original[0],'TCB_EVAL_KEY(uint8)','bytes32',kind))[0];
    const [issued,expires]=await call(original[0],'getCollateralValidity(bytes32)','uint64,uint64',key);
    const block=await rpc('eth_getBlockByNumber',['latest',false]),timestamp=BigInt(block.timestamp);
    if(BigInt(issued)===0n || timestamp<BigInt(issued) || timestamp>BigInt(expires)) {
      const payload=JSON.parse(fs.readFileSync(path.join(root,`evm/forge-test/assets/v2/local-fork/${name}-tcbeval.json`)));
      const evalOwner=(await call(original[0],'owner()','address'))[0];
      await rpc('anvil_impersonateAccount',[evalOwner]);impersonated.add(evalOwner);
      await rpc('anvil_setBalance',[evalOwner,'0x56bc75e2d63100000']);
      const role=(await call(original[0],'ATTESTER_ROLE()','uint256'))[0];
      await tx(`tcbEvaluation.${name}.grantAttester`,original[0],calldata('grantRoles(address,uint256)',owner,role),evalOwner);
      await tx(`tcbEvaluation.${name}.upsert`,original[0],signedTupleCalldata('upsertTcbEvaluationData((string,bytes))',[],
        JSON.stringify(payload.tcbEvaluationDataNumbers),'0x'+payload.signature.replace(/^0x/,'')));
    }
    const number=(await call(legacyRouter,'getStandardTcbEvaluationDataNumber(uint8)','uint32',kind))[0];
    if(Number(number)!==20)throw new Error('Standard evaluation differs from the prepared fixture set; prepare matching signed collateral');
  }
  for(let i=0;i<keys.length;i++) if((await call(legacyRouter,`${keys[i]}()`,'address'))[0]!==original[i]) throw new Error('Legacy Router changed during isolated deployment');
  report.status='DEPLOYMENT_AND_COLLATERAL_TRANSACTIONS_PASS'; report.sdkAndZkAcceptance='NOT_RUN';save();
} catch(error) { report.status='FAILED';report.error=error.message;save();throw error; }
finally { for(const account of impersonated) await rpc('anvil_stopImpersonatingAccount',[account]); }
console.log(`Local transaction report: ${output}`);
