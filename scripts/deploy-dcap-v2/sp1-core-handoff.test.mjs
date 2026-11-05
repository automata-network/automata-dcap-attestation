// Wrapper/control-flow tests only: the fake Docker never generates a ZK proof.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const runner = fileURLToPath(new URL('./sp1-core-on-mac.sh', import.meta.url));
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dcap-core-wrapper-test-'));
  t.after(() => fs.rmSync(root, {recursive:true, force:true}));
  const handoff = path.join(root, 'handoff');
  const bin = path.join(root, 'bin');
  const result = path.join(root, 'result');
  fs.mkdirSync(handoff); fs.mkdirSync(bin);
  const content = 'MOCK INPUT ONLY\n';
  fs.writeFileSync(path.join(handoff, 'input.bin'), content);
  fs.writeFileSync(path.join(handoff, 'SHA256SUMS'), createHash('sha256').update(content).digest('hex')+'  input.bin\n');
  fs.writeFileSync(path.join(bin, 'docker'), `#!/usr/bin/env node
const a=process.argv.slice(2);
if(a[0]==='image') console.log(a.includes('--format') ? (process.env.MOCK_ARCH || 'linux/arm64') : '[{"mock":true}]');
else if(a[0]==='info') console.log(process.env.MOCK_MEMORY || '17179869184');
else if(a[0]==='version') console.log('MOCK DOCKER ONLY');
else if(a[0]==='run') { console.log('MOCK RUN; NO PROOF GENERATED'); process.exit(Number(process.env.MOCK_EXIT || 0)); }
`, {mode:0o755});
  return {root,handoff,result,run(extra={}) { return spawnSync('bash', [runner,handoff,result], {
    encoding:'utf8', timeout:15000, env:{...process.env,PATH:bin+path.delimiter+process.env.PATH,...extra}
  }); }};
}

test('refuses existing result without changing it', t => {
  const f=fixture(t); fs.mkdirSync(f.result);
  assert.equal(f.run().status,2); assert.deepEqual(fs.readdirSync(f.result),[]);
});
test('rejects changed handoff input before creating results', t => {
  const f=fixture(t); fs.appendFileSync(path.join(f.handoff,'input.bin'),'changed');
  assert.notEqual(f.run().status,0); assert.equal(fs.existsSync(f.result),false);
});
test('rejects wrong runtime platform', t => {
  const f=fixture(t); assert.notEqual(f.run({MOCK_ARCH:'linux/amd64'}).status,0);
  assert.equal(fs.existsSync(f.result),false);
});
test('rejects insufficient Docker memory', t => {
  const f=fixture(t); assert.equal(f.run({MOCK_MEMORY:'8589934592'}).status,2);
  assert.equal(fs.existsSync(f.result),false);
});
for (const code of [0,17]) test(`archives mock runtime exit ${code} and preserves status`, t => {
  const f=fixture(t); const run=f.run({MOCK_EXIT:String(code)});
  assert.equal(run.status,code,run.stderr);
  assert.equal(fs.readFileSync(path.join(f.result,'exit.txt'),'utf8').trim(),String(code));
  assert.equal(fs.existsSync(path.join(f.result,'return.tar.gz')),true);
  const listing=spawnSync('tar',['-tzf',path.join(f.result,'return.tar.gz')],{encoding:'utf8'});
  assert.equal(listing.status,0); assert.match(listing.stdout,/exit\.txt/);
  assert.doesNotMatch(listing.stdout,/return\.tar\.gz/);
  // The wrapper must not fabricate PASS/proof files; only the real helper does.
  assert.equal(fs.existsSync(path.join(f.result,'PASS.txt')),false);
  assert.equal(fs.existsSync(path.join(f.result,'proof.bin')),false);
});
