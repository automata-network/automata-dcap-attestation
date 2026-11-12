import assert from 'node:assert/strict';
import {test} from 'node:test';
import {mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync, existsSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';

const source = dirname(fileURLToPath(import.meta.url));
const commit = 'a'.repeat(40);

// Guard/packaging checks only; mocks are never proof or build evidence.
function fixture(t, {platform = 'Darwin', version = '3.1.0'} = {}) {
  const root = mkdtempSync(join(tmpdir(), 'dcap-r0-mac-test-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const runner = join(root, 'scripts/fork-dcap-v2/risc0-v31-on-mac.sh');
  const builder = join(root, 'rust-crates/libraries/zkvm/methods/docker');
  const bin = join(root, 'bin');
  for (const path of [dirname(runner), builder, bin]) mkdirSync(path, {recursive: true});
  copyFileSync(join(source, 'risc0-v31-on-mac.sh'), runner);
  copyFileSync(join(source, '../../rust-crates/libraries/zkvm/methods/docker/common.sh'), join(builder, 'common.sh'));
  function stub(name, body) { writeFileSync(join(bin, name), `#!/bin/bash\n${body}\n`, {mode: 0o755}); }
  stub('git', `case "$*" in *rev-parse*) echo ${commit};; esac`);
  stub('uname', `echo ${platform}`);
  stub('cargo', `echo 'cargo-risczero ${version}'`);
  stub('r0vm', `echo 'risc0-r0vm ${version}'`);
  stub('rustc', 'exit 0');
  stub('docker', 'exit 0');
  writeFileSync(join(builder, 'reproduce-official.sh'), `#!/bin/bash
mkdir -p "$TMPDIR/dcap-risc0-official-pair.test"
echo mock-failed-build > "$TMPDIR/dcap-risc0-official-pair.test/evidence.tar.gz"
echo mock-docker-failure
exit 42
`);
  const output = join(root, 'result');
  const run = () => spawnSync('bash', [runner, commit, output], {
    encoding: 'utf8', env: {...process.env, PATH: `${bin}:${process.env.PATH}`},
  });
  return {run, output};
}

test('Mac runner rejects missing arguments', () => {
  const r = spawnSync('bash', [join(source, 'risc0-v31-on-mac.sh')], {encoding: 'utf8'});
  assert.equal(r.status, 2);
  assert.match(r.stderr, /Usage:/);
});

test('Mac runner refuses VM execution before creating output', t => {
  const {run, output} = fixture(t, {platform: 'Linux'});
  const r = run();
  assert.equal(r.status, 2);
  assert.match(r.stderr, /Mac, not the VM/);
  assert.equal(existsSync(output), false);
});

test('Mac runner refuses old proving tools', t => {
  const {run, output} = fixture(t, {version: '3.0.3'});
  assert.notEqual(run().status, 0);
  assert.equal(existsSync(output), false);
});

test('Mac runner preserves an existing result directory', t => {
  const {run, output} = fixture(t);
  mkdirSync(output);
  writeFileSync(join(output, 'checkpoint'), 'preserve');
  assert.notEqual(run().status, 0);
  assert.equal(readFileSync(join(output, 'checkpoint'), 'utf8'), 'preserve');
});

test('Mac runner preserves the failed stage status and a limited return bundle', t => {
  const {run, output} = fixture(t);
  const r = run();
  assert.equal(r.status, 42, r.stdout + r.stderr);
  assert.equal(readFileSync(join(output, 'exit-status.txt'), 'utf8').trim(), '42');
  const listing = spawnSync('tar', ['-tzf', join(output, 'return.tar.gz')], {encoding: 'utf8'});
  assert.equal(listing.status, 0, listing.stderr);
  assert.match(listing.stdout, /strict-evidence.tar.gz/);
  assert.match(listing.stdout, /strict-build.log/);
  assert.doesNotMatch(listing.stdout, /builds\/|target\/|witness\//);
});
