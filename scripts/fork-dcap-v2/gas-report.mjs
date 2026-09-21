#!/usr/bin/env node
// Read-only receipt/trace reconciliation on the isolated Anvil fork.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const [deploymentFile, ...rest] = process.argv.slice(2);
const output=rest.pop();
if (!output || !rest.length || fs.existsSync(output)) throw new Error('Usage: gas-report.mjs DEPLOYMENT_REPORT SDK_REPORT [SDK_REPORT ...] NEW_REPORT.json');
const deployment=JSON.parse(fs.readFileSync(deploymentFile));
const sdks=rest.map(file=>JSON.parse(fs.readFileSync(file)));
if(deployment.status!=='DEPLOYMENT_AND_COLLATERAL_TRANSACTIONS_PASS' || sdks.some(sdk=>sdk.status!=='PASS')) throw new Error('Only successful reports can enter the positive gas table');
const endpoint=new URL(deployment.rpc);
if(endpoint.protocol!=='http:' || !['127.0.0.1','[::1]'].includes(endpoint.hostname) || endpoint.username) throw new Error('Local Anvil only');
async function rpc(method, params=[]) {
  if(!['anvil_nodeInfo','eth_getTransactionByHash','eth_getTransactionReceipt','debug_traceTransaction','eth_call'].includes(method)) throw new Error('Read-only methods only');
  const response=await fetch(endpoint,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(60000)});
  const body=await response.json();if(body.error) throw new Error(JSON.stringify(body.error));return body.result;
}
const node=await rpc('anvil_nodeInfo');
const chainId=deployment.origin?.environment?.chainId;
const profiles={
  11155111:{block:11689923,hash:'0x4ee0fcdc5b220406b457d0242cc280f0313ff1cc72bd5d9fdf041808881c8096',hardfork:'Osaka'},
  11155420:{block:48718178,hash:'0x95b1d91f43a9f6209524114ef04d8d49ba47a82743460bce939fa10a97bbac8c',hardfork:'Karst',network:'optimism'},
};
const profile=profiles[chainId];
if(!profile || node.environment?.chainId!==chainId || node.forkConfig?.forkBlockNumber!==profile.block ||
   deployment.origin.forkConfig?.forkBlockNumber!==profile.block || deployment.origin.currentBlockHash!==profile.hash ||
   deployment.origin.hardFork!==profile.hardfork || node.hardFork!==profile.hardfork ||
   (profile.network && (node.network!==profile.network || deployment.origin.network!==profile.network)) ||
   (!profile.network && ((node.network && node.network!=='ethereum') ||
     (deployment.origin.network && deployment.origin.network!=='ethereum'))))throw new Error('Wrong or unreviewed fork/runtime');
const names=new Map(Object.entries(deployment.contracts).map(([name,value])=>[value.address.toLowerCase(),name]));
const registryFile=path.resolve(path.dirname(fileURLToPath(import.meta.url)), `../../rust-crates/libraries/network-registry/deployment/current/${chainId}/onchain_pccs.json`);
for(const [name,address] of Object.entries(JSON.parse(fs.readFileSync(registryFile)))) {
  if(!names.has(address.toLowerCase())) names.set(address.toLowerCase(),`registry label: ${name}`);
}
for(const [name,address] of Object.entries(deployment.originalRouter)) names.set(address.toLowerCase(),name);
names.set(deployment.legacy.PCCSRouter.toLowerCase(),'PCCSRouter');
names.set('0x0000000000000000000000000000000000000100','P256 precompile');
names.set('0x0000000000000000000000000000000000000002','SHA256 precompile');
names.set('0x0000000000000000000000000000000000000006','BN254 add precompile');
names.set('0x0000000000000000000000000000000000000007','BN254 multiply precompile');
names.set('0x0000000000000000000000000000000000000008','BN254 pairing precompile');
if(chainId===11155111)for(const [address,name] of [
  ['0x925d8331ddc0a1f0d96e68cf073dfe1d92b69187','RISC Zero universal router'],
  ['0x724d375b5b622e15f0e64e9deb76a4cb17877797','RISC Zero 3.0 emergency-stop wrapper'],
  ['0x2a098988600d87650fb061ffaff08b97149fa84d','RISC Zero 3.0 Groth16 verifier'],
  ['0x397a5f7f3dbd538f23de225b51f532c34448da9b','SP1 universal gateway'],
  ['0x50acfbedecf4cbe350e1a86fc6f03a821772f1e5','SP1 v5.0.0 Groth16 verifier'],
])names.set(address,name); // Labels from the fixed Sepolia route readbacks.
const transactions=[...deployment.transactions.map(t=>({label:t.label,hash:t.hash||t.receipt?.transactionHash})),
  ...sdks.flatMap(sdk=>sdk.results.map(t=>({label:t.label || `${sdk.sdk}-sdk.${t.backend ? `zk.backend-${t.backend}` : `raw.${t.fixture}`}.${t.automatic?'default':'explicit'}`,hash:t.transactionHash,backend:t.backend})))];
if(new Set(transactions.map(t=>t.hash?.toLowerCase())).size!==transactions.length) throw new Error('Duplicate transaction would inflate the gas report');
const results=[];
for(const item of transactions) {
  if(!item.hash) throw new Error('Missing confirmed transaction hash');
  const receipt=await rpc('eth_getTransactionReceipt',[item.hash]);
  const transaction=await rpc('eth_getTransactionByHash',[item.hash]);
  const trace=await rpc('debug_traceTransaction',[item.hash,{tracer:'callTracer'}]);
  if(BigInt(receipt.status)!==1n) throw new Error('Failed receipt in positive gas report');
  if(BigInt(trace.gasUsed)!==BigInt(receipt.gasUsed)) throw new Error('Trace root does not reconcile to receipt');
  const buckets=new Map();
  let callCount=0;
  function visit(node,depth=0) {
    callCount++;
    const children=node.calls||[];
    const inclusive=BigInt(node.gasUsed||0);
    const residual=inclusive-children.reduce((sum,c)=>sum+BigInt(c.gasUsed||0),0n);
    const address=(node.to||receipt.contractAddress||'creation').toLowerCase();
    const key=depth===0?'transaction root residual':address;
    const current=buckets.get(key)||{address,label:depth===0?'entrypoint + transaction accounting residual':names.get(address)||(address===transaction.from.toLowerCase()?'transaction caller / refund recipient':'other deployed dependency'),calls:0,residualGas:0n};
    current.calls++;current.residualGas+=residual;buckets.set(key,current);
    children.forEach(c=>visit(c,depth+1));
  }
  visit(trace);
  const sum=[...buckets.values()].reduce((s,b)=>s+b.residualGas,0n);
  if(sum!==BigInt(receipt.gasUsed)) throw new Error('Non-overlapping bucket sum mismatch');
  const bytes=Buffer.from(transaction.input.slice(2),'hex');
  let journalMetadata;
  if(item.backend) {
    // Both tested V2 ZK overloads carry journal as their first dynamic ABI
    // argument. Decode the confirmed transaction, not a guessed fixture label.
    if(bytes.length<68)throw new Error('Missing ZK calldata head');
    const offset=BigInt('0x'+bytes.subarray(4,36).toString('hex'))+4n;
    if(offset+32n>BigInt(bytes.length))throw new Error('Invalid journal offset');
    const start=Number(offset);
    const length=BigInt('0x'+bytes.subarray(start,start+32).toString('hex'));
    if(length<9n || offset+32n+length>BigInt(bytes.length))throw new Error('Invalid journal length');
    const journal=bytes.subarray(start+32,start+32+Number(length));
    if(journal.readUInt16BE(0)!==2 || journal.readUInt16BE(2)!==1 || journal[4]!==6)throw new Error('Unexpected OutputV2 format');
    // V2 ZK overloads: short (journal,backend,proof) = 35a9f4b4 using the strict
    // default ID; long (…,identifier,evalNumber,minCheck) = 6f1b4168.
    const selector=bytes.subarray(0,4).toString('hex');
    if(!['35a9f4b4','6f1b4168'].includes(selector) || bytes.length<(selector==='6f1b4168'?196:100))throw new Error('Unexpected V2 ZK overload');
    const backend=BigInt('0x'+bytes.subarray(36,68).toString('hex'));
    if(backend!==BigInt(item.backend) || ![1n,2n].includes(backend))throw new Error('SDK backend does not match confirmed calldata');
    const proofOffset=4n+BigInt('0x'+bytes.subarray(68,100).toString('hex'));
    if(proofOffset+32n>BigInt(bytes.length))throw new Error('Invalid proof offset');
    const proofAt=Number(proofOffset),proofLength=BigInt('0x'+bytes.subarray(proofAt,proofAt+32).toString('hex'));
    const proof=bytes.subarray(proofAt+32,proofAt+32+Number(proofLength));
    // Framing by proof family: SP1 v6 Groth16 EVM encoding is 356 bytes
    // (selector 0x4388a21c); RISC Zero Groth16 seals are 260 bytes.
    const expectedProofLength=proof.subarray(0,4).toString('hex')==='4388a21c'?356n:260n;
    if(proofLength!==expectedProofLength || proofOffset+32n+proofLength>BigInt(bytes.length))throw new Error('Unexpected EVM proof frame');
    // Resolve an automatic ID at the confirmed transaction's historical block,
    // not at latest, so subsequent configuration changes cannot rewrite evidence.
    // programIdentifierV2(uint8) keeps selector 0xbe29ec0f.
    const programId=selector==='6f1b4168'?'0x'+bytes.subarray(100,132).toString('hex'):
      await rpc('eth_call',[{to:transaction.to,data:'0xbe29ec0f'+backend.toString(16).padStart(64,'0')},receipt.blockNumber]);
    if(!/^0x[0-9a-fA-F]{64}$/.test(programId))throw new Error('Invalid confirmed program ID');
    const minCheck=selector==='6f1b4168'?bytes[195]!==0:false;
    journalMetadata={formatMajor:2,formatMinor:1,quoteVersion:journal.readUInt16BE(5),quoteBodyType:journal.readUInt16BE(7),journalBytes:journal.length,journalSha256:crypto.createHash('sha256').update(journal).digest('hex'),backend:Number(backend),programId,minCheck,proofSelector:'0x'+proof.subarray(0,4).toString('hex'),proofSha256:crypto.createHash('sha256').update(proof).digest('hex')};
    item.label=item.label.replace(/\.zk\.backend-([12])\./,`.zk.backend-$1.quote-v${journalMetadata.quoteVersion}.body-${journalMetadata.quoteBodyType}.`);
  }
  const zeroBytes=bytes.filter(b=>b===0).length;
  const nonzeroBytes=bytes.length-zeroBytes;
  const accessList=transaction.accessList || [];
  const calldataGas=zeroBytes*4+nonzeroBytes*16;
  const accessListGas=accessList.reduce((sum,item)=>sum+2400+1900*item.storageKeys.length,0);
  if(transaction.authorizationList?.length)throw new Error('Authorization-list intrinsic accounting is outside this harness');
  const creationGas=transaction.to===null?32000+2*Math.ceil(bytes.length/32):0;
  const standardIntrinsicGas=21000+calldataGas+accessListGas+creationGas;
  const row={...item,journalMetadata,gasUsed:Number(BigInt(receipt.gasUsed)),calldataBytes:bytes.length,zeroBytes,nonzeroBytes,
    standardIntrinsicGas,calldataGas,accessListGas,creationGas,
    dataFloorGas:21000+10*(zeroBytes+4*nonzeroBytes),
    netGasAboveStandardIntrinsic:Number(BigInt(receipt.gasUsed))-standardIntrinsicGas,
    effectiveGasPrice:receipt.effectiveGasPrice,
    executionFeeWei:(BigInt(receipt.gasUsed)*BigInt(receipt.effectiveGasPrice)).toString(),
    chainSpecificReceiptFields:Object.fromEntries(Object.entries(receipt).filter(([key])=>/^(l1|operator)/i.test(key))),
    callCount,traceReconciliation:'PASS',buckets:[...buckets.values()].map(b=>({...b,residualGas:Number(b.residualGas)}))};
  results.push(row);console.log(`${item.label}: receipt=${row.gasUsed} calls=${callCount} reconciled`);
}
fs.writeFileSync(output,JSON.stringify({schema:1,chainId,forkBlock:profile.block,hardfork:node.hardFork,status:'PASS',
  accounting:'Each node contributes gasUsed minus direct child gasUsed. Buckets telescope to the receipt and are not summed inclusive call gas. Intrinsic components and EIP-7623 data floor are shown separately, not added again to buckets. netGasAboveStandardIntrinsic still reflects refunds/floors and is not gross EVM execution. Root residual includes transaction accounting and entrypoint work.',
  limitations:'Only supplied successful deployment/raw/ZK transactions. Chain-specific fee fields are retained if the node supplies them; absence is not zero. executionFeeWei is gasUsed times effectiveGasPrice, not an all-in L2 fee claim. No market-price conversion or full cold/warm/legacy comparison.',results},null,2)+'\n',{flag:'wx'});
