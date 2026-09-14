#!/usr/bin/env node
// Fork-only transaction replay. Never takes a private key or a public write RPC.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const [endpoint, output, profile='sepolia-osaka'] = process.argv.slice(2);
if (!output || fs.existsSync(output)) throw new Error('Usage: anvil-deploy.mjs http://127.0.0.1:PORT NEW_REPORT.json [sepolia-osaka|op-sepolia-karst]');
const pins={
  'sepolia-osaka':{chainId:11155111,block:11689923,hash:'0x4ee0fcdc5b220406b457d0242cc280f0313ff1cc72bd5d9fdf041808881c8096',hardfork:'Osaka'},
  'op-sepolia-karst':{chainId:11155420,block:48718178,hash:'0x95b1d91f43a9f6209524114ef04d8d49ba47a82743460bce939fa10a97bbac8c',hardfork:'Karst',network:'optimism'},
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
const report = {schema:1, status:'IN_PROGRESS', rpc:endpoint, origin:info, profile, transactions:[], contracts:{}, legacy:registry};
const save = () => fs.writeFileSync(output, JSON.stringify(report,null,2)+'\n');
save();
const call = async (to, sig, returns, ...args) => JSON.parse(cast('abi-decode','--json',`f()(${returns})`,
  await rpc('eth_call', [{to,data:calldata(sig,...args)},'latest'])));
const router = registry.PCCSRouter, legacy = registry.AutomataDcapAttestationFee;
const owner = (await call(router,'owner()','address'))[0];
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
try {
  const keys = ['tcbEvalDaoAddr','pcsDaoAddr','pckDaoAddr','pckHelperAddr','crlHelperAddr','fmspcTcbHelperAddr'];
  const original=[];
  for(const key of keys) original.push((await call(router,`${key}()`,'address'))[0]);
  report.originalRouter=Object.fromEntries(keys.map((k,i)=>[k,original[i]])); report.owner=owner; save();
  const p256=(await call(original[1],'P256_VERIFIER()','address'))[0];
  const helper=await deploy('PCKHelper');
  const fee=await deploy('AutomataDcapAttestationFeeV2','address',[owner]);
  const bp=(await call(legacy,'getBp()','uint16'))[0];
  await send('fee.copyBp',fee,'setBp(uint16)',bp);
  await send('fee.pauseV2',fee,'setZkV2Paused(bool)',true);
  for(const version of [3,4,5]) {
    const verifier=await deploy(`V${version}QuoteVerifier`,'address,address',[p256,router]);
    await send(`fee.setV${version}`,fee,'setQuoteVerifier(address)',verifier);
    await send(`router.authorizeV${version}`,router,'setAuthorized(address,bool)',verifier,true);
  }
  await send('router.authorizeFeeV2',router,'setAuthorized(address,bool)',fee,true);
  for(const kind of [1,2]) {
    const universal=(await call(legacy,'zkVerifier(uint8)','address',kind))[0];
    const id=(await call(legacy,'programIdentifier(uint8)','bytes32',kind))[0];
    const ids=(await call(legacy,'programIdentifiers(uint8)','bytes32[]',kind))[0];
    if(BigInt(universal)===0n && BigInt(id)===0n && ids.length===0) continue;
    if(profile==='op-sepolia-karst')throw new Error('OP backend scope changed; review instead of enabling ZK');
    if(BigInt(universal)===0n || BigInt(id)===0n) throw new Error('Incomplete legacy backend');
    await send(`fee.legacyConfig.${kind}`,fee,'setZkConfiguration(uint8,(bytes32,address))',kind,`(${id},${universal})`);
    for(const other of ids) if(other!==id) await send(`fee.legacyId.${kind}`,fee,'updateProgramIdentifier(uint8,bytes32)',kind,other);
    if(ids.some(other=>other!==id)) await send(`fee.legacyDefault.${kind}`,fee,'updateProgramIdentifier(uint8,bytes32)',kind,id);
    const v2=kind===1 ? '0x9d4a47be495ab06a6a84b24d856a13a68312d8fdea487bcb8aa6931a322f9b9b' : '0x000544ec0a86e3860bac6c329267c270beed1f7be600519128022a02f4b9f170';
    await send(`fee.v2Config.${kind}`,fee,'setZkConfigurationV2(uint8,(bytes32,address))',kind,`(${v2},${universal})`);
  }
  // The pinned Ethereum Sepolia Fee's genesis-to-pin ZkRouteAdded/ZkRouteFrozen queries
  // both returned [], as recorded in the fork report. Do not generalize this
  // no-override migration to other chains without their route inventory.
  // OP has no registered backend/ID; full historical route inventory remains
  // separate from this raw-only local rehearsal and is not claimed complete.
  report.routeMigrationScope=profile==='sepolia-osaka'?'observed-empty-Fee-overrides':'raw-only-no-active-backends; full-history-open';
  for(let i=0;i<keys.length;i++) if((await call(router,`${keys[i]}()`,'address'))[0]!==original[i]) throw new Error('Router changed before switch');
  const next=[...original];next[3]=helper;
  await send('router.switchPckHelper',router,'setConfig(address,address,address,address,address,address)',...next);
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
    const fmspc='0x'+expected.slice(20,32), tcbType=fixtureName==='ata-sgx-v3'?0:1;
    const dao=(await call(router,'fmspcTcbDaoVersionedAddr(uint32)','address',fixture.tcbEvaluationDataNumber))[0];
    const key=(await call(dao,'FMSPC_TCB_KEY(uint8,bytes6,uint32)','bytes32',tcbType,fmspc,3))[0];
    const hash=(await call(dao,'getTcbInfoContentHash(bytes32)','bytes32',key))[0];
    const validNow=async (target, collateralKey)=> {
      const [issued,expires]=await call(target,'getCollateralValidity(bytes32)','uint64,uint64',collateralKey);
      const block=await rpc('eth_getBlockByNumber',['latest',false]);
      const timestamp=BigInt(block.timestamp);
      return BigInt(issued)!==0n && BigInt(issued)<=timestamp && timestamp<=BigInt(expires);
    };
    if(hash.toLowerCase()!=='0x'+expected.slice(130,194) || !await validNow(dao,key)) {
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
      if((await call(dao,'getTcbInfoContentHash(bytes32)','bytes32',key))[0].toLowerCase()!=='0x'+expected.slice(130,194)) throw new Error('Async hash mismatch');
    }
    if(!await validNow(dao,key)) throw new Error('FMSPC collateral not valid at the actual block timestamp');
    const qe=(await call(router,'qeIdDaoVersionedAddr(uint32)','address',fixture.tcbEvaluationDataNumber))[0];
    const qeKey=(await call(qe,'ENCLAVE_ID_KEY(uint256,uint256)','bytes32',tcbType===0?0:2,4))[0];
    if((await call(qe,'getIdentityContentHash(bytes32)','bytes32',qeKey))[0].toLowerCase()!=='0x'+expected.slice(194,258) || !await validNow(qe,qeKey)) {
      const qeOwner=(await call(qe,'owner()','address'))[0];
      await rpc('anvil_impersonateAccount',[qeOwner]);impersonated.add(qeOwner);
      await rpc('anvil_setBalance',[qeOwner,'0x56bc75e2d63100000']);
      const role=(await call(qe,'ATTESTER_ROLE()','uint256'))[0];
      await tx(`${fixtureName}.qe.grantAttester`,qe,calldata('grantRoles(address,uint256)',owner,role),qeOwner);
      const identity=JSON.parse(fixture.qeIdentityJson);
      await tx(`${fixtureName}.qe.upsert`,qe,signedTupleCalldata('upsertEnclaveIdentity(uint256,uint256,(string,bytes))',[tcbType===0?0:2,4],
        JSON.stringify(identity.enclaveIdentity),'0x'+identity.signature.replace(/^0x/,'')));
    }
    if((await call(qe,'getIdentityContentHash(bytes32)','bytes32',qeKey))[0].toLowerCase()!=='0x'+expected.slice(194,258) || !await validNow(qe,qeKey)) throw new Error('QE upsert hash/validity mismatch');
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
    const number=(await call(router,'getStandardTcbEvaluationDataNumber(uint8)','uint32',kind))[0];
    if(Number(number)!==20)throw new Error('Standard evaluation differs from the prepared fixture set; prepare matching signed collateral');
  }
  report.status='DEPLOYMENT_AND_COLLATERAL_TRANSACTIONS_PASS'; report.sdkAndZkAcceptance='NOT_RUN';save();
} catch(error) { report.status='FAILED';report.error=error.message;save();throw error; }
finally { for(const account of impersonated) await rpc('anvil_stopImpersonatingAccount',[account]); }
console.log(`Local transaction report: ${output}`);
