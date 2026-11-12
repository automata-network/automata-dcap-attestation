import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import childProcess from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
import {readState, requireNoOverrides, verifyDisabled, fee, owner, creationBlock, runtimeHash, main} from './disable-sepolia-v11-risc0.mjs';

test('history scan covers every block, filters only RISC Zero, and refuses overrides or RPC gaps', async () => {
  const ranges = [];
  await requireNoOverrides(async (method, [filter]) => {
    assert.equal(method, 'eth_getLogs');
    assert.equal(filter.address, fee);
    assert.equal(filter.topics[1], '0x' + '1'.padStart(64, '0'));
    ranges.push([Number(BigInt(filter.fromBlock)), Number(BigInt(filter.toBlock))]);
    return [];
  }, creationBlock + 60000);
  assert.deepEqual(ranges, [[creationBlock, creationBlock + 29999],
    [creationBlock + 30000, creationBlock + 59999], [creationBlock + 60000, creationBlock + 60000]]);
  await assert.rejects(requireNoOverrides(async () => [{}], creationBlock), /explicit route history/);
  await assert.rejects(requireNoOverrides(async () => null, creationBlock), /Invalid route history/);
  await assert.rejects(requireNoOverrides(async () => { throw Error('RPC timeout'); }, creationBlock), /RPC timeout/);
});

test('wrong chain or bytecode stops before configuration reads', async () => {
  await assert.rejects(readState(async () => '0x1'), /Sepolia only/);
  await assert.rejects(readState(async method => {
    if (method === 'eth_chainId') return '0xaa36a7';
    if (method === 'eth_getBlockByNumber') return {hash: '0x123', number: '0xb8e000'};
    if (method === 'eth_getCode') return '0x6000';
    assert.fail('Unexpected configuration read');
  }), /Unexpected Fee bytecode/);
});

test('readback requires only RISC Zero verifier to change and preserves ID inventory', () => {
  const before = {values: {owner, risc0Verifier: '0x123', risc0Id: '0x456', risc0Ids: '0x456',
    sp1Verifier: '0x789', feeBp: '0x1', rawV3: '0x987'}};
  const after = {values: {...before.values, risc0Verifier: '0x' + '0'.repeat(64)}};
  verifyDisabled(before, after);
  assert.throws(() => verifyDisabled(before, before), /readback failed/);
  for (const key of ['owner', 'risc0Id', 'risc0Ids', 'sp1Verifier', 'feeBp', 'rawV3']) {
    assert.throws(() => verifyDisabled(before, {values: {...after.values, [key]: 'changed'}}), /readback failed/);
  }
});

test('broadcast requires an explicit keystore argument; no write occurs on import', async () => {
  for (const args of [['--broadcast'], ['--broadcast', 'account', '--extra'], ['--yes'], ['--private-key', 'secret']]) {
    await assert.rejects(main(args), /Usage:/);
  }
});

test('CLI dry-run never sends; explicit broadcast uses valid cast arguments and verifies readback', async t => {
  const execute = childProcess.execFileSync;
  const cast = (...args) => execute('cast', args.map(String), {encoding: 'utf8'}).trim();
  const id = '0x' + 'a'.repeat(64);
  const zeroWord = '0x' + '0'.repeat(64);
  const addressWord = '0x' + owner.slice(2).padStart(64, '0');
  const values = new Map();
  for (const sig of ['owner()', 'getBp()', 'zkVerifier(uint8)', 'programIdentifier(uint8)',
    'programIdentifiers(uint8)', 'quoteVerifiers(uint16)']) {
    const args = sig.includes('uint8') ? [1, 2] : sig.includes('uint16') ? [3, 4, 5] : [undefined];
    for (const arg of args) values.set(cast('calldata', sig, ...(arg === undefined ? [] : [arg])),
      sig.startsWith('programIdentifiers') ? cast('abi-encode', 'f(bytes32[])', `[${id}]`) :
        sig.startsWith('programIdentifier') ? id : addressWord);
  }
  const verifierCall = cast('calldata', 'zkVerifier(uint8)', 1);
  const calldata = cast('calldata', 'setZkConfiguration(uint8,(bytes32,address))', 1, `(${id},0x${'0'.repeat(40)})`);
  let sends = 0;
  const rpcUrl = process.env.DCAP_RPC_URL;
  process.env.DCAP_RPC_URL = 'https://unit-test.invalid';
  t.after(() => { if (rpcUrl === undefined) delete process.env.DCAP_RPC_URL; else process.env.DCAP_RPC_URL = rpcUrl; });
  t.mock.method(console, 'log', () => {});
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url, 'https://unit-test.invalid');
    const {method, params} = JSON.parse(options.body);
    let result;
    if (method === 'eth_chainId') result = '0xaa36a7';
    else if (method === 'eth_getBlockByNumber') result = {hash: id, number: '0x' + (creationBlock + 1).toString(16)};
    else if (method === 'eth_getCode') result = '0x6000';
    else if (method === 'eth_getLogs') result = [];
    else if (method === 'eth_call') {
      assert.equal(params[0].to, fee);
      result = params[0].data === calldata ? '0x' : values.get(params[0].data);
      assert.ok(result, 'Unexpected call');
    } else assert.fail(`Unexpected RPC ${method}`);
    return {ok: true, status: 200, json: async () => ({result})};
  });
  const mocked = t.mock.method(childProcess, 'execFileSync', (bin, args, options) => {
    if (bin === 'cast' && args[0] === 'keccak' && args[1] === '0x6000') return runtimeHash;
    if (bin === 'cast' && args[0] === 'send') {
      assert.deepEqual(args, ['send', fee, calldata, '--rpc-url', 'https://unit-test.invalid',
        '--account', 'test-owner', '--from', owner, '--confirmations', '2', '--json']);
      // Real CLI parser, with --help: never signs, connects or broadcasts.
      execute(bin, [...args, '--help'], {encoding: 'utf8'});
      sends++;
      values.set(verifierCall, zeroWord);
      return JSON.stringify({status: '0x1', transactionHash: id});
    }
    return execute(bin, args, options);
  });
  syncBuiltinESMExports();
  t.after(() => { mocked.mock.restore(); syncBuiltinESMExports(); });
  await main([]);
  assert.equal(sends, 0);
  await main(['--broadcast', 'test-owner']);
  assert.equal(sends, 1);
  await main(['--broadcast', 'test-owner']);
  assert.equal(sends, 1, 'Already-disabled invocation must not send again');
});

// Optional read-only integration against an archive RPC; never broadcasts.
test('live Sepolia dry-run preserves the real ID and simulates the exact setter', {
  skip: !process.env.DCAP_SEPOLIA_READONLY_RPC,
}, async () => {
  const {createRpcRequest} = await import('./publish-v2.mjs');
  const request = createRpcRequest(process.env.DCAP_SEPOLIA_READONLY_RPC);
  const state = await readState(request);
  await requireNoOverrides(request, Number(BigInt(state.block.number)));
  const [backend, config] = JSON.parse(execFileSync('cast', ['calldata-decode', '--json',
    'setZkConfiguration(uint8,(bytes32,address))', state.calldata], {encoding: 'utf8'}));
  assert.equal(Number(backend), 1);
  assert.equal(config[0], state.values.risc0Id);
  assert.equal(BigInt(config[1]), 0n);
  await request('eth_call', [{to: fee, from: owner, data: state.calldata}, state.block.number]);
});
