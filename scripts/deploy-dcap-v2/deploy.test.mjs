import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import childProcess from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {deploymentContracts, evaluationInventory, readerInventory, redactError, forgeArgument, main} from './deploy.mjs';
import {registryHashes, sp1Provenance} from './replacement.mjs';

const address = n => '0x' + n.toString(16).padStart(40, '0');
test('Foundry array arguments omit JSON quotes and retain scalar values', () => {
  assert.equal(forgeArgument(['0xe71e6620', '0x4388a21c']), '[0xe71e6620,0x4388a21c]');
  assert.equal(forgeArgument([1, 2]), '[1,2]');
  assert.equal(forgeArgument([]), '[]');
  assert.equal(forgeArgument(false), 'false');
  assert.equal(forgeArgument(address(1)), address(1));
});
test('real Foundry ABI parser accepts selector, address, evaluation and empty arrays', () => {
  const word = n => BigInt(n).toString(16).padStart(64, '0');
  const cases = [
    ['bytes4[]', ['0xe71e6620', '0x4388a21c'], ['e71e6620'.padEnd(64, '0'), '4388a21c'.padEnd(64, '0')]],
    ['address[]', [address(1), address(0xdead)], [word(1), word(0xdead)]],
    ['uint8[]', [1, 2], [word(1), word(2)]],
    ['uint32[]', [20, 21], [word(20), word(21)]],
    ['bytes4[]', [], []],
    ['address[]', [], []],
  ];
  for (const [type, values, words] of cases) {
    const encoded = execFileSync('cast', ['abi-encode', `f(${type})`, forgeArgument(values)], {encoding:'utf8'}).trim();
    assert.equal(encoded, '0x' + word(32) + word(values.length) + words.join(''));
  }
});
test('tooling-only recovery enables ZK once without repeating completed deployment or program stages', async t => {
  const out=fs.mkdtempSync(path.join(os.tmpdir(),'dcap-resume-test-'));
  t.after(()=>fs.rmSync(out,{recursive:true,force:true}));
  const write=(name,value)=>fs.writeFileSync(path.join(out,name),JSON.stringify(value));
  const read=name=>JSON.parse(fs.readFileSync(path.join(out,name),'utf8'));
  const sourceDir=fileURLToPath(new URL('../../rust-crates/libraries/network-registry/deployment/v2.0/560048/',import.meta.url));
  const source=JSON.parse(fs.readFileSync(path.join(sourceDir,'manifest.json'),'utf8'));
  const pinned='a'.repeat(40), current='b'.repeat(40), id=n=>'0x'+n.toString(16).padStart(64,'0');
  const programs=[false,true].map((minCheck,i)=>({backend:1,minCheck,id:id(i+1),verifier:address(90),proofSelector:'0xe71e6620',
    buildSdkVersion:'3.1.0',buildSourceCommit:pinned,artifactSha256:'c'.repeat(64),evidenceSha256:'d'.repeat(64)}));
  const config={mode:'replace-entrypoint',chainId:560048,owner:address(9),accounts:{[address(9)]:'test-owner'},programs};
  const reused=Object.fromEntries(Object.entries(source.plan.contracts).filter(([key])=>key!=='AutomataDcapAttestationV2'));
  const plan={...source.plan,mode:config.mode,sourceCommit:pinned,owner:config.owner,programs,deploySp1Groth16V6:false,
    legacyFee:source.plan.contracts.AutomataDcapAttestationV2,legacyRouter:reused.PCCSRouterV2,
    reusedContracts:reused,contracts:{...reused,AutomataDcapAttestationV2:address(99)},
    sourceRegistryHashes:registryHashes(sourceDir),sourceSp1Provenance:sp1Provenance(source),sourceDeploymentTx:id(100)};
  const completed=['deploy','router-reader','migrate-sp1','backend-1-strict','backend-1-minimal'];
  const state={commit:pinned,configDigest:createHash('sha256').update(JSON.stringify(config)).digest('hex'),
    stages:Object.fromEntries(completed.map(name=>[name,true])),transactions:[id(10)]};
  write('config.json',config); write('plan.json',plan); write('state.json',state);
  write('before.json',{legacy:{routerOwner:config.owner,migration:{sp1:{programs:[],routes:[],defaultId:id(20),selector:'0x4388a21c'}}}});
  for(const name of completed) write(`${name}.broadcast.json`,{transactions:name==='deploy'
    ?[{transactionType:'CREATE',contractName:'AutomataDcapAttestationV2',contractAddress:address(99),hash:id(10)}]:[]});

  const realExecute=childProcess.execFileSync, realRead=fs.readFileSync, realExists=fs.existsSync, scripts=[];
  const broadcastPath=fileURLToPath(new URL('../../evm/broadcast/DeployDcapV2.s.sol/560048/enableReplacementZk-latest.json',import.meta.url));
  t.mock.method(fs,'readFileSync',(file,...args)=>file===broadcastPath?JSON.stringify({transactions:[{hash:id(11)}]}):realRead(file,...args));
  t.mock.method(fs,'existsSync',file=>file===broadcastPath||realExists(file));
  const execute=t.mock.method(childProcess,'execFileSync',(bin,args)=>{
    if(bin==='git') {
      if(args[0]==='rev-parse') return current;
      if(args[0]==='diff'&&args.includes('-z')) return 'scripts/deploy-dcap-v2/deploy.mjs\0';
      assert.ok(['diff','ls-files','merge-base'].includes(args[0])); return '';
    }
    assert.deepEqual([bin,...args],['cast','wallet','address','--account','test-owner']); return config.owner;
  });
  const spawn=t.mock.method(childProcess,'spawnSync',(bin,args)=>{
    if(bin===process.execPath) {assert.equal(args[1],'check');return {status:0};}
    assert.equal(bin,'forge');
    if(args[0]==='build') return {status:0};
    assert.equal(args[0],'script'); scripts.push(args);
    const start=args.indexOf('--sig'), sig='enableReplacementZk(uint256,address,address,address,uint8[],bytes4[])';
    assert.equal(args[start+1],sig);
    assert.deepEqual(args.slice(start+2,start+8),['560048',config.owner,plan.legacyFee,address(99),'[1,2]','[0xe71e6620,0x4388a21c]']);
    realExecute('cast',['calldata',sig,...args.slice(start+2,start+8)],{encoding:'utf8'});
    return {status:0}; // Never spawn a real transaction sender.
  });
  syncBuiltinESMExports();
  t.after(()=>{execute.mock.restore();spawn.mock.restore();syncBuiltinESMExports();});
  const previous={DCAP_RPC_URL:process.env.DCAP_RPC_URL,ETHERSCAN_API_KEY:process.env.ETHERSCAN_API_KEY};
  process.env.DCAP_RPC_URL='https://unit-test.invalid';process.env.ETHERSCAN_API_KEY='test-key';
  t.after(()=>{for(const [key,value] of Object.entries(previous)) {if(value===undefined) delete process.env[key];else process.env[key]=value;}});
  t.mock.method(console,'log',()=>{});
  t.mock.method(globalThis,'fetch',async(url,options)=>{
    assert.equal(url,'https://unit-test.invalid');const {method}=JSON.parse(options.body);
    const values={eth_chainId:'0x88bb0',eth_getBlockByNumber:{number:'0x100'},eth_getCode:'0x',
      eth_getTransactionReceipt:{status:'0x1',blockNumber:'0x101'}};
    assert.ok(Object.hasOwn(values,method));return {ok:true,json:async()=>({result:values[method]})};
  });
  await main([path.join(out,'config.json'),out,'--broadcast']);
  assert.equal(scripts.length,2);assert.equal(scripts.filter(args=>args.includes('--broadcast')).length,1);
  const after=read('state.json');
  assert.equal(after.commit,pinned);assert.equal(after.coordinatorCommit,current);
  assert.equal(read('plan.json').sourceCommit,pinned);assert.equal(after.status,'WAIT_FINALIZATION');
  assert.deepEqual(after.stages,{...state.stages,'enable-zk':true});assert.equal(after.running,undefined);
  assert.deepEqual(after.transactions,[id(10),id(11)]);
  await main([path.join(out,'config.json'),out,'--broadcast']);
  assert.equal(scripts.length,2,'Waiting for finality must not resend the enable transaction');
  assert.equal(fs.existsSync(path.join(out,'coordinator.lock')),false);
  write('config.json',{...config,owner:address(8)});
  await assert.rejects(main([path.join(out,'config.json'),out,'--broadcast']),/Checkpoint configuration changed/);
});
test('cast process errors cannot expose endpoint credentials', () => {
  const url = 'https://rpc.example/v2/private-api-key?token=secret-value';
  const text = redactError(`cast call --rpc-url ${url}: private-api-key secret-value`, url);
  assert.ok(!text.includes('private-api-key') && !text.includes('secret-value') && !text.includes(url));
});
test('deduplicates sorted evaluation inventory without assuming a default version', () => {
  assert.deepEqual(evaluationInventory({A_tcbeval_21: '', B_tcbeval_20: '', C_tcbeval_21: '', Other: ''}), [20, 21]);
});
test('only accepts six unique CREATE deployment records', () => {
  const names = ['AutomataDcapAttestationV2', 'PCCSRouter', 'PCKHelper', 'V3QuoteVerifier', 'V4QuoteVerifier', 'V5QuoteVerifier'];
  const txs = names.map((contractName, i) => ({contractName, contractAddress: address(i + 1), transactionType: 'CREATE'}));
  assert.equal(deploymentContracts(txs).AutomataDcapAttestationV2, address(1));
  assert.throws(() => deploymentContracts(txs.slice(1)), /six/);
  assert.throws(() => deploymentContracts([...txs, txs[0]]), /Duplicate/);
  assert.throws(() => deploymentContracts(txs.map(t => ({...t, transactionType: 'CALL'}))), /six/);
});
test('resolver dedup preserves one DAO and the actual owner of every resolver', async () => {
  const legacy = {router: {tcbEvalDaoAddr: address(1), pcsDaoAddr: address(2), pckDaoAddr: address(3)},
    evaluations: {21: {qeIdDaoVersionedAddr: address(4), fmspcTcbDaoVersionedAddr: address(5)}}};
  const readers = await readerInventory(legacy, async (to, sig) => {
    if (sig.startsWith('resolver')) return to === address(5) ? address(11) : address(10);
    return to === address(11) ? address(21) : address(20);
  });
  assert.deepEqual(readers, [{dao: address(1), resolver: address(10), owner: address(20)},
    {dao: address(5), resolver: address(11), owner: address(21)}]);
});
