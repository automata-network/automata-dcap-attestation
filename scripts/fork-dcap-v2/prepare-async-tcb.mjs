#!/usr/bin/env node
// Generate local test payloads with the existing QPL pure encoder. No RPC,
// transaction signing or changes to the QPL checkout. Generated Rust is a
// mechanical extraction into a fresh temporary build directory, not a new codec.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {execFileSync} from 'node:child_process';

const [qplRoot, fixturePath, output] = process.argv.slice(2);
if (!output || fs.existsSync(output)) throw new Error('Usage: prepare-async-tcb.mjs QPL_ROOT FIXTURE NEW_OUTPUT.json');
const encoderPath = path.join(qplRoot, 'automata-dcap-qpl-tool/src/helper/tcb_fmspc_async.rs');
const source = fs.readFileSync(encoderPath, 'utf8');
const hash = crypto.createHash('sha256').update(source).digest('hex');
const expected = 'a6689dbef7655d53bb4222b2d42d362d3317fbf2bbf2ea42d00eee13dba7c212';
if (hash !== expected) throw new Error(`QPL encoder differs from reviewed e110b001 source: ${hash}`);
function section(start, end) {
  const a = source.indexOf(start), b = source.indexOf(end, a);
  if (a < 0 || b <= a) throw new Error('Pinned encoder section missing');
  return source.slice(a, b);
}
const generated = [
  '#![allow(dead_code)]\n',
  section('const TOP_FIELDS:', 'fn async_parse_batch_size()'),
  section('#[derive(Clone, Copy)]', 'pub async fn upsert_tcb_fmspc_func('),
  section('/* ----- async payload planning ----- */', 'pub(crate) async fn send_transaction'),
  section('pub(crate) fn extract_tcb_info_str(', 'pub(crate) fn fallback_tcb_version('),
  `
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filename = std::env::args().nth(1).ok_or("fixture required")?;
    let fixture: serde_json::Value = serde_json::from_slice(&std::fs::read(filename)?)?;
    let outer = fixture["tcbInfoJson"].as_str().ok_or("tcbInfoJson missing")?;
    let raw = extract_tcb_info_str(outer)?;
    let inner: serde_json::Value = serde_json::from_str(&raw)?;
    let fmspc: [u8; 6] = hex::decode(inner["fmspc"].as_str().ok_or("fmspc missing")?)?.try_into().map_err(|_| "fmspc size")?;
    let locator = TcbLocator { tcb_type: parse_tcb_type(inner["id"].as_str().ok_or("id missing")?), fmspc,
        version: inner["version"].as_u64().ok_or("version missing")?.try_into()? };
    let plan = build_async_plan(raw.as_bytes(), locator)?;
    let levels: Vec<_> = plan.levels.chunks(3).enumerate().map(|(i, chunk)| serde_json::json!({
        "start": i*3, "count": chunk.len(), "payload": format!("0x{}", hex::encode(build_level_batch_payload(chunk, plan.has_tdx_components, locator.version)))
    })).collect();
    let identities: Vec<_> = plan.identities.chunks(3).enumerate().map(|(i, chunk)| serde_json::json!({
        "start": i*3, "count": chunk.len(), "payload": format!("0x{}", hex::encode(build_identity_batch_payload(chunk)))
    })).collect();
    println!("{}", serde_json::json!({ "raw": raw, "rawLength": raw.len(),
        "basicPayload": format!("0x{}", hex::encode(plan.basic_payload)),
        "topLevelOrder": format!("0x{}", hex::encode(plan.top_level_order)),
        "levels": levels, "identities": identities }));
    Ok(())
}
`,
].join('\n');
const build = fs.mkdtempSync(path.join(os.tmpdir(), 'dcap-qpl-encoder.'));
fs.mkdirSync(path.join(build, 'src'));
fs.writeFileSync(path.join(build, 'src/main.rs'), generated, {flag: 'wx'});
fs.writeFileSync(path.join(build, 'Cargo.toml'), '[package]\nname="dcap-qpl-encoder"\nversion="0.0.0"\nedition="2021"\n[dependencies]\nserde_json="=1.0.145"\nhex="=0.4.3"\n', {flag: 'wx'});
const result = execFileSync('cargo', ['run', '--offline', '--quiet', '--target-dir', path.join(build, 'target'), '--manifest-path', path.join(build, 'Cargo.toml'), '--', path.resolve(fixturePath)],
  {encoding: 'utf8', maxBuffer: 4 * 1024 * 1024, env: {...process.env, CARGO_BUILD_JOBS: '2'}});
const payload = JSON.parse(result);
payload.encoder = {repo: 'automata-network/automata-dcap-qpl', commit: 'e110b001ac7af69b1cbf2d51293d29a404d5b983', sourceSha256: hash};
payload.fixtureSha256 = crypto.createHash('sha256').update(fs.readFileSync(fixturePath)).digest('hex');
fs.writeFileSync(output, JSON.stringify(payload, null, 2) + '\n', {flag: 'wx'});
console.log(`Saved ${output}; generated build retained at ${build}. No chain writes.`);
