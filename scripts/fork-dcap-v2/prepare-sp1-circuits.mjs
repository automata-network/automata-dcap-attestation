#!/usr/bin/env node
// Verify/extract the existing official setup. Never generates a keypair.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {execFileSync} from 'node:child_process';

const [archive, destination] = process.argv.slice(2);
if (!destination || fs.existsSync(destination)) throw new Error('Usage: prepare-sp1-circuits.mjs ARCHIVE NEW_DIRECTORY');
const source = 'https://sp1-circuits.s3-us-east-2.amazonaws.com/v5.0.0-groth16.tar.gz';
const expected = '6cbc2c155c41001e81efd81119bd3d4f32313fcd3184df383d50225315b73104';
async function sha256(file) {
  const hash = crypto.createHash('sha256');
  for await (const chunk of fs.createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}
if (fs.statSync(archive).size !== 3025985400 || await sha256(archive) !== expected) {
  throw new Error('Official v5.0.0 artifact archive differs from the recorded download');
}
const files = ['Groth16Verifier.sol', 'groth16_witness.json', 'groth16_vk.bin', 'constraints.json',
  'groth16_pk.bin', 'SP1VerifierGroth16.sol', 'groth16_circuit.bin'];
const listing = execFileSync('tar', ['-tzf', archive], {encoding: 'utf8'}).trim().split('\n');
const allowed = new Set(['./', ...files.map(f => `./${f}`)]);
if (listing.length !== allowed.size || new Set(listing).size !== allowed.size || listing.some(f => !allowed.has(f))) {
  throw new Error('Unexpected archive path, duplicate or missing member');
}
const types = execFileSync('tar', ['-tvzf', archive], {encoding: 'utf8'}).trim().split('\n');
if (types.some(line => !/^[-d]/.test(line))) throw new Error('Links and special archive members are forbidden');
fs.mkdirSync(path.dirname(destination), {recursive: true});
fs.mkdirSync(destination);
execFileSync('tar', ['-xzf', path.resolve(archive), '--no-same-owner', '--no-same-permissions', '-C', destination]);
const entries = [];
for (const name of files) {
  const file = path.join(destination, name);
  if (!fs.lstatSync(file).isFile()) throw new Error(`Not a regular file: ${name}`);
  entries.push({name, bytes: fs.statSync(file).size, sha256: await sha256(file)});
}
const verifier = fs.readFileSync(path.join(destination, 'SP1VerifierGroth16.sol'), 'utf8');
if (!verifier.includes('a4594c59')) throw new Error('Unexpected SP1 proof-route identifier');
fs.writeFileSync(path.join(destination, 'download-manifest.json'), JSON.stringify({
  source, archiveBytes: 3025985400, archiveSha256: expected, setup: 'existing official v5.0.0; no new setup',
  scope: 'Download integrity and expected route. Real proof acceptance by the deployed verifier is still required.', files: entries,
}, null, 2) + '\n', {flag: 'wx'});
console.log(`Verified official setup at ${path.resolve(destination)}. This is not a proof-verification result.`);
