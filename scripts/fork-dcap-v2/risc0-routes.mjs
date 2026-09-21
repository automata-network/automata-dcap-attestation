#!/usr/bin/env node
// Read back every Sepolia selector in the pinned upstream deployment catalog.
// The router has no route-change events: this does not assert exhaustiveness
// for arbitrary administrator calls outside the upstream catalog.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const [stateFile,output]=process.argv.slice(2);
if(!output || fs.existsSync(output))throw new Error('Usage: risc0-routes.mjs PINNED_STATE_INVENTORY NEW_REPORT.json');
const state=JSON.parse(fs.readFileSync(stateFile)),endpoint=new URL(state.rpc);
if(endpoint.protocol!=='https:' || endpoint.username || endpoint.password || endpoint.search || state.chainId!==11155111 || state.block!==11689923)throw new Error('Reviewed public Sepolia pin only');
const catalogPath=path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../evm/lib/risc0-ethereum/contracts/deployment.toml');
const catalog=fs.readFileSync(catalogPath,'utf8');
const section=catalog.split('[chains.ethereum-sepolia]\n')[1]?.split('\n[chains.ethereum-holesky]')[0];
if(!section)throw new Error('Missing upstream Sepolia catalog');
const router=section.match(/^router = "(0x[0-9a-fA-F]{40})"/m)?.[1];
if(router?.toLowerCase()!==state.backends?.risc0?.universalVerifier?.toLowerCase())throw new Error('Catalog/router mismatch');
const entries=section.split('[[chains.ethereum-sepolia.verifiers]]').slice(1).map(s=>{
  const get=key=>s.match(new RegExp('^'+key+' = "([^"\\n]+)"','m'))?.[1];
  return {name:get('name'),version:get('version'),selector:get('selector'),verifier:get('verifier'),estop:get('estop'),stopped:/^stopped = true/m.test(s),unroutable:/^unroutable = true/m.test(s)};
});
if(!entries.length || entries.some(e=>!/^0x[0-9a-f]{8}$/.test(e.selector)))throw new Error('Invalid deployment catalog');
const cast=(...args)=>execFileSync('cast',args,{encoding:'utf8',maxBuffer:4*1024*1024}).trim();
const at='0x'+BigInt(state.block).toString(16);
async function rpc(method,params) {
  if(!['eth_getCode','eth_getBlockByNumber','eth_call'].includes(method))throw new Error('Read-only methods only');
  const r=await fetch(endpoint,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(20000)});
  const body=await r.json();if(body.error)throw new Error(JSON.stringify(body.error));return body.result;
}
const call=async(to,sig,returns,...args)=>JSON.parse(cast('abi-decode','--json',`f()(${returns})`,await rpc('eth_call',[{to,data:cast('calldata',sig,...args.map(String))},at])))[0];
const report={schema:1,status:'IN_PROGRESS',chainId:state.chainId,block:state.block,blockHash:state.blockHash,router,
  catalogSha256:crypto.createHash('sha256').update(catalog).digest('hex'),scope:'Pinned upstream catalog candidates; arbitrary uncatalogued mapping entries are not enumerable. The existing universal router is reused unchanged, not migrated/redeployed.',routes:[],errors:[]};
const save=()=>fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n');save();
try {
  for(const entry of entries) {
    const row={...entry,actual:await call(router,'verifiers(bytes4)','address',entry.selector)};
    const value=BigInt(row.actual);
    row.state=value===0n?'UNSET':value===1n?'REMOVED':'ROUTED';
    if(value>1n) {
      const code=await rpc('eth_getCode',[row.actual,at]);
      if(code==='0x')throw new Error('Routed verifier has no code');
      row.codeHash=cast('keccak',code);
      row.underlying=await call(row.actual,'verifier()','address');
      row.paused=await call(row.actual,'paused()','bool');
      row.catalogAddressMatches=row.actual.toLowerCase()===entry.estop.toLowerCase() && row.underlying.toLowerCase()===entry.verifier.toLowerCase();
    }
    report.routes.push(row);save();
  }
  if((await rpc('eth_getBlockByNumber',[at,false])).hash!==state.blockHash)throw new Error('Block hash mismatch');
  report.status='CATALOG_READBACK_COMPLETE_NOT_EXHAUSTIVE';save();
  console.log(`${report.routes.length} RISC Zero catalog selectors read back; inspect observed pause/removal states.`);
}catch(error){report.status='PARTIAL';report.errors.push(error.message);save();throw error;}
