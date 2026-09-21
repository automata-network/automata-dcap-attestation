#!/usr/bin/env node
// Linux diagnostic watchdog; RSS polling is NOT a kernel hard memory limit.
// Match a unique proof output argument, and terminate only that process family.
import fs from 'node:fs';
import {execFileSync} from 'node:child_process';
const [commPrefix, outputArgument, completionFile] = process.argv.slice(2);
if (!completionFile || !outputArgument.startsWith('/')) throw new Error('Usage: watch-proof.mjs COMM_PREFIX ABSOLUTE_OUTPUT_ARGUMENT COMPLETION_FILE');
const rssLimit = Number(process.env.DCAP_PROOF_MAX_RSS_KIB || 8388608);
if (!Number.isSafeInteger(rssLimit) || rssLimit <= 0 || rssLimit > 11534336) throw new Error('RSS guard must be positive and at most 11 GiB');
let tick = 0;
const timer = setInterval(() => {
  if (fs.existsSync(completionFile)) { console.log('watchdog finished'); clearInterval(timer); return; }
  const rows = execFileSync('ps', ['-eo','pid=,ppid=,rss=,comm='], {encoding:'utf8', timeout:5000})
    .trim().split('\n').map(s => s.trim().split(/\s+/));
  const roots = rows.filter(r => r[3].startsWith(commPrefix)).filter(r => {
    try { return fs.readFileSync('/proc/'+r[0]+'/cmdline','utf8').split('\0').includes(outputArgument); }
    catch { return false; }
  });
  for (const root of roots) {
    const family = new Set([root[0]]);
    let changed = true;
    while (changed) { changed = false; for (const r of rows) if (family.has(r[1]) && !family.has(r[0])) {family.add(r[0]); changed=true;} }
    const rss = rows.filter(r => family.has(r[0])).reduce((sum,r) => sum+Number(r[2]),0);
    const available = Number(fs.readFileSync('/proc/meminfo','utf8').match(/^MemAvailable:\s+(\d+)/m)[1]);
    const stop = rss > rssLimit || available < 1572864;
    if (tick%5 === 0 || stop) console.log(new Date().toISOString(), 'root='+root[0], 'rss_kib='+rss, 'available_kib='+available, 'stop='+stop);
    if (stop) for (const pid of [...family].reverse()) {
      try { process.kill(Number(pid),'SIGTERM'); } catch (e) { if(e.code !== 'ESRCH') throw e; }
    }
  }
  tick++;
},1000);
