// One-time conversion of unreleased inline-body 2.1 golden vectors to compact 2.1.
// Preserve quote/collateral/input bytes and hash the independently frozen report body.
import fs from 'node:fs';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const root = new URL('../../evm/forge-test/assets/v2/', import.meta.url);
function compact(hex) {
  const old = Buffer.from(hex.replace(/^0x/, '').trim(), 'hex');
  if (old.readUInt16BE(49) !== 289) throw Error('Not an original inline-body vector');
  const length = old.readUInt16BE(51), end = 289 + length;
  if (![384, 584, 648].includes(length) || end > old.length) throw Error('Invalid old body');
  const bodyHash = Buffer.from(execFileSync('cast', ['keccak', '0x'+old.subarray(289,end).toString('hex')], {encoding:'utf8'}).trim().slice(2), 'hex');
  const advisory = old.subarray(end), offsets = Buffer.alloc(4);
  offsets.writeUInt16BE(advisory.length ? 317 : 0, 0);
  offsets.writeUInt16BE(advisory.length, 2);
  return Buffer.concat([old.subarray(0,49), offsets, old.subarray(57,289), bodyHash, advisory]);
}
if (process.argv[2] !== '--write') throw Error('Explicit --write required; never run in tests');
for (const name of ['sgx-empty','tdx10-advisories','tdx15-relaunch','verified-v3','verified-v4']) {
  const file=new URL(name+'.hex',root), old=fs.readFileSync(file,'utf8');
  fs.writeFileSync(file,compact(old).toString('hex')+'\n');
}
for (const name of fs.readdirSync(new URL('fixtures/',root)).filter(n=>n.endsWith('.json'))) {
  const file=new URL('fixtures/'+name,root), f=JSON.parse(fs.readFileSync(file));
  const journal=compact(f.expectedJournal);
  f.expectedJournal='0x'+journal.toString('hex');
  f.expectedJournalSha256=createHash('sha256').update(journal).digest('hex');
  fs.writeFileSync(file,JSON.stringify(f,null,2)+'\n');
}
