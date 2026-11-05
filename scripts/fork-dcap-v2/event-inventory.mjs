#!/usr/bin/env node
// Bounded, read-only pagination for non-enumerable Fee/Router configuration.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
const [chain,endpoint,block,output]=process.argv.slice(2);
if(!output || fs.existsSync(output)) throw new Error('Usage: event-inventory.mjs CHAIN PUBLIC_RPC PINNED_BLOCK NEW_REPORT.json');
const url=new URL(endpoint);
if(url.username || url.password || url.search) throw new Error('Public RPC only; no credentials in reports');
const registry=path.resolve(path.dirname(fileURLToPath(import.meta.url)),`../../rust-crates/libraries/network-registry/deployment/current/${chain}/dcap.json`);
const contracts=JSON.parse(fs.readFileSync(registry));
const addresses=[contracts.AutomataDcapAttestationFee,contracts.PCCSRouter];
const signatures=['ZkRouteAdded(uint8,bytes4,address)','ZkRouteFrozen(uint8,bytes4)',
  'SetCallerAuthorization(address,bool)','UpdateCallerRestriction(bool)',
  'UpdateConfig(address,address,address,address,address,address)',
  'UpdateQeIdDaoVersionedAddr(uint32,address)','UpdateFmspcTcbDaoVersionedAddr(uint32,address)'];
const topics=Object.fromEntries(signatures.map(sig=>[execFileSync('cast',['keccak',sig],{encoding:'utf8'}).trim(),sig]));
const last=Number(block), step=50000;
if(!Number.isSafeInteger(last) || last<0 || Math.ceil((last+1)/step)>1000) throw new Error('Explicit safe block range required');
const hex=n=>'0x'+BigInt(n).toString(16);
async function rpc(method,params=[]) {
  if(!['eth_chainId','eth_getBlockByNumber','eth_getLogs'].includes(method)) throw new Error('Read-only RPC only');
  const res=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(30000)});
  if(!res.ok) throw new Error(`HTTP ${res.status}`);
  const body=await res.json();if(body.error) throw new Error(JSON.stringify(body.error));return body.result;
}
if(BigInt(await rpc('eth_chainId'))!==BigInt(chain)) throw new Error('Wrong chain');
const pin=await rpc('eth_getBlockByNumber',[hex(last),false]);
if(!pin?.hash) throw new Error('Missing pinned block');
const report={schema:1,chainId:Number(chain),rpc:endpoint,block:last,blockHash:pin.hash,complete:false,
  scope:'Fee/Router events only. Universal-verifier and storage authorization histories are separate.',
  addresses,topics,pages:[],logs:[]};
const save=()=>fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n');save();
try {
  for(let from=0;from<=last;from+=step) {
    const to=Math.min(from+step-1,last);
    const logs=await rpc('eth_getLogs',[{address:addresses,fromBlock:hex(from),toBlock:hex(to),topics:[Object.keys(topics)]}]);
    if(!Array.isArray(logs) || logs.some(log=>log.removed || Number(BigInt(log.blockNumber))<from || Number(BigInt(log.blockNumber))>to)) throw new Error('Invalid log response');
    report.pages.push({from,to,count:logs.length});report.logs.push(...logs);save();
    if(report.pages.length%20===0) console.log(`${chain}: scanned through ${to}; logs=${report.logs.length}`);
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  const confirm=await rpc('eth_getBlockByNumber',[hex(last),false]);
  if(confirm?.hash!==pin.hash) throw new Error('Pinned block changed');
  const keys=report.logs.map(log=>`${log.transactionHash}:${log.logIndex}`);
  if(new Set(keys).size!==keys.length) throw new Error('Duplicate log response');
  report.complete=true;save();
  console.log(`${chain}: full Fee/Router event range read; ${report.logs.length} logs. State replay/review still required.`);
} catch(error) {report.error=error.message;save();throw error;}
