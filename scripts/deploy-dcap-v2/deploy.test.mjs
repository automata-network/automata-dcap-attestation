import test from 'node:test';
import assert from 'node:assert/strict';
import {deploymentContracts, evaluationInventory, readerInventory, redactError} from './deploy.mjs';

const address = n => '0x' + n.toString(16).padStart(40, '0');
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
