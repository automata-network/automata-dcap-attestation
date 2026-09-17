#!/usr/bin/env python3
"""Validate paired-build evidence before extracting it; never execute archived scripts.

Usage: verify-returned.py BACKEND ARCHIVE COMMIT NEW_OUTPUT_DIRECTORY
Only regular files/directories from the known evidence layout are accepted.
AppleDouble metadata is ignored. This validates build evidence, NOT a ZK proof.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile


def check(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify(backend, archive, commit, output):
    scripts = Path(__file__).resolve().parent
    repo = Path(subprocess.check_output(["git", "-C", str(scripts), "rev-parse", "--show-toplevel"], text=True).strip())
    check(backend in ("risc0", "sp1"), "unsupported backend")
    check(re.fullmatch(r"[0-9a-f]{40}", commit), "full commit required")
    output = Path(output)
    check(not output.exists(), "output already exists")
    pins = {
        "risc0": "risczero/risc0-guest-builder:r0.1.88.0@sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3",
        "sp1": "ghcr.io/succinctlabs/sp1:v5.2.2@sha256:7b5582c3773b0238192fbd5d6a37f5eb3166d3a47a1a1798ecc7847d2194d04f",
    }
    allowed = {"a.log", "b.log", "preflight.log", "comparison.txt", "environment.txt", "exit-status.txt",
               "image-reference.txt", "source-commit.txt", "host-tools.sha256", "inputs.sha256", "image-inspect.json"}
    allowed.update("scripts/" + f for f in ("common.sh", "docker-no-cache.sh", "reproduce-official.sh"))
    for run in ("a", "b"):
        allowed.update(f"{run}/results/{f}" for f in ("lock.sha256", "native-id.txt", "metadata.json",
                                                     backend + ".elf", "artifact.sha256", "native-id.stdout"))
    members = {}
    seen = set()
    total = 0
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            name = member.name.rstrip("/")
            path = PurePosixPath(name)
            check(name and not path.is_absolute() and ".." not in path.parts and "\\" not in name, "unsafe archive path")
            check(name not in seen, "duplicate archive member")
            seen.add(name)
            check(member.isfile() or member.isdir(), "archive links/special files forbidden")
            total += member.size
            check(total <= 128 * 1024 * 1024 and len(seen) <= 128, "oversized evidence")
            if path.name.startswith("._"):
                continue
            if member.isdir():
                check(name in ("scripts", "a", "b", "a/results", "b/results"), "unexpected directory")
                continue
            check(name in allowed, "unexpected member: " + name)
            members[name] = tar.extractfile(member).read()
    check(set(members) == allowed, "incomplete evidence")
    text = lambda name: members[name].decode().strip()
    check(text("source-commit.txt") == commit, "wrong source commit")
    check(text("exit-status.txt") == "0", "build failed")
    check(text("comparison.txt") == "PASS: independent official Docker builds match in bytes and native ID.", "missing comparison")
    check(text("image-reference.txt") == pins[backend], "wrong image")
    inspect = json.loads(members["image-inspect.json"])
    check(len(inspect) == 1 and inspect[0]["Os"] == "linux" and inspect[0]["Architecture"] == "amd64", "wrong image platform")
    check(inspect[0]["Id"] == pins[backend].split("@", 1)[1], "wrong inspected image")
    inputs = {}
    for line in text("inputs.sha256").splitlines():
        checksum, name = line.split(None, 1)
        name = name.lstrip("*")
        check(name not in inputs and re.fullmatch(r"[0-9a-f]{64}", checksum), "invalid input manifest")
        inputs[name] = checksum
    check(set(inputs) == {"source.tar", "scripts/common.sh", "scripts/docker-no-cache.sh", "scripts/reproduce-official.sh"}, "wrong input set")
    source = subprocess.check_output(["git", "-C", str(repo), "archive", "--format=tar", commit])
    check(inputs["source.tar"] == digest(source), "source archive hash mismatch")
    for name in inputs.keys() - {"source.tar"}:
        check(digest(members[name]) == inputs[name], "archived harness hash mismatch")
        check(members[name] == (scripts / PurePosixPath(name).name).read_bytes(), "local harness differs")
    guest = "risc0/guest" if backend == "risc0" else "sp1/program"
    lockpath = f"rust-crates/libraries/zkvm/methods/{guest}/Cargo.lock"
    lock = subprocess.check_output(["git", "-C", str(repo), "show", f"{commit}:{lockpath}"])
    for run in ("a", "b"):
        prefix = f"{run}/results/"
        check(text(prefix + "lock.sha256").split() == [digest(lock), lockpath], "guest lock mismatch")
        check(text(prefix + "artifact.sha256").split() == [digest(members[prefix + backend + ".elf"]), backend + ".elf"], "artifact hash mismatch")
        native = text(prefix + "native-id.txt")
        check(re.fullmatch(r"0x[0-9a-f]{64}", native), "invalid native ID")
        raw_ids = re.findall(r"(?:0x)?([0-9a-fA-F]{64})", text(prefix + "native-id.stdout"))
        check(len(raw_ids) == 1 and "0x" + raw_ids[0].lower() == native, "ID output mismatch")
        check(b"dcap-" in members[run + ".log"] and b"Finished" in members[run + ".log"], "missing compilation log")
        json.loads(members[prefix + "metadata.json"])
    for name in (backend + ".elf", "native-id.txt", "lock.sha256"):
        check(members["a/results/" + name] == members["b/results/" + name], "A/B mismatch: " + name)
    summary = {"status": "PAIRED_BUILD_EVIDENCE_PASS_NOT_EXECUTION_OR_PROOF", "backend": backend,
               "sourceCommit": commit, "sourceArchiveSha256": inputs["source.tar"], "image": pins[backend],
               "archiveSha256": digest(Path(archive).read_bytes()), "harnessInputs": inputs,
               "lockSha256": digest(lock), "artifactSha256": digest(members["a/results/" + backend + ".elf"]),
               "artifactBytes": len(members["a/results/" + backend + ".elf"]), "nativeId": text("a/results/native-id.txt")}
    output.mkdir(parents=True)
    for name, data in members.items():
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    (output / "verified-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    verify(*sys.argv[1:])
