"""Prove stage: attempt to demonstrate a finding by execution.

A candidate finding without a proof is, in practice, an entry on a triage backlog. Where the
bug class admits it, this stage asks a model to reduce the defect to a self-contained script
and then runs it: printing ``VULNERABLE`` proves the mechanism, ``SAFE`` disproves it.

**This executes model-generated code, so it is opt-in (`--prove`) and never runs by default.**
The sandbox is defence in depth, not a boundary you should rely on for hostile input:

* a separate process with a hard wall-clock timeout and process-tree kill,
* an empty temporary working directory, deleted afterwards,
* a scrubbed environment - no Azure or CI credentials, no proxy, no API keys,
* `-I` isolated mode, so the repository and user site-packages are off `sys.path`,
* an in-process socket guard that refuses every non-loopback connection, which closes the
  path from a prompt-injected PoC to cloud instance metadata (169.254.169.254) and to
  exfiltration of anything it finds,
* stdin closed, output truncated.

Run it in CI or a container, not on a workstation holding credentials. Only mechanisms that
reduce to pure computation are provable this way; anything needing a live service, a race
window, or privileged access is correctly reported as NOT_PROVABLE by the model.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .agents import PROVER_SYSTEM
from .config import Config
from .findings import Finding, ProofState, severity_rank
from .panel import Panel

log = logging.getLogger("mdash.prove")

# Classes whose mechanism can be demonstrated by pure computation. Anything else needs a
# deployed service and is out of scope for this stage.
_PROVABLE_HINTS = (
    "xxe", "entity", "billion laughs", "xml", "redos", "regular expression", "catastrophic",
    "traversal", "path", "deserial", "pickle", "yaml", "injection", "parsing", "comment",
    "canonical", "truncat", "unicode", "normaliz", "integer", "overflow", "race", "toctou",
    "timing", "hash", "randomness", "predictable", "escape", "sanitiz",
)

_MAX_SCRIPT_BYTES = 40_000

# Environment allowlist. Everything else - AZURE_*, GITHUB_TOKEN, OPENAI/API keys, proxies -
# is dropped so a generated script cannot reach anything with the runner's identity.
_ENV_KEEP = ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG", "LC_ALL", "TZ", "COMSPEC")

# Prepended to every generated PoC. The script that runs here was written by a model whose
# prompt contains source code from the repository under scan, so its content is attacker
# influenced whenever the repository is. A scrubbed environment stops it from *holding* a
# credential, but on any cloud runner an outbound request to the instance metadata service
# (169.254.169.254) mints one on demand, and any other outbound request exfiltrates whatever
# the PoC has read. Nothing in a legitimate proof-of-concept for the classes in
# _PROVABLE_HINTS needs the network: they all reduce to pure computation.
#
# Patching socket.connect covers the whole stdlib surface (http.client, urllib, ftplib,
# smtplib) and requests/httpx, because all of them ultimately call it. This is a guardrail
# that raises the cost of an attack, NOT a security boundary - in-process patches are
# defeatable by code that goes looking for them. The boundary is running this in a
# disposable container, which is what --prove's documentation tells you to do.
_NETWORK_GUARD = '''\
import socket as _mdash_socket

_MDASH_LOOPBACK = {"127.0.0.1", "::1", "localhost", "0.0.0.0", ""}


def _mdash_check(address):
    host = address[0] if isinstance(address, (tuple, list)) and address else address
    if isinstance(host, (bytes, bytearray)):
        host = host.decode("utf-8", "replace")
    if str(host) not in _MDASH_LOOPBACK:
        raise PermissionError(
            "mdash sandbox: outbound network denied (%s). Proofs must be self-contained."
            % (host,)
        )


def _mdash_wrap(fn):
    def wrapper(self, address, *args, **kwargs):
        _mdash_check(address)
        return fn(self, address, *args, **kwargs)
    return wrapper


_mdash_socket.socket.connect = _mdash_wrap(_mdash_socket.socket.connect)
_mdash_socket.socket.connect_ex = _mdash_wrap(_mdash_socket.socket.connect_ex)


def _mdash_create_connection(address, *args, **kwargs):
    _mdash_check(address)
    raise PermissionError("mdash sandbox: outbound network denied.")


_mdash_socket.create_connection = _mdash_create_connection
del _mdash_wrap
# --- end mdash sandbox preamble; model-generated proof-of-concept follows ---
'''


def _sanitise_for_log(text: str, limit: int = 120) -> str:
    """Flatten model-authored text before it reaches a log line.

    Finding titles come from the model and land in logs that other tools parse. Embedded
    CR/LF would let a crafted title forge additional log records (CWE-117).
    """
    flattened = " ".join((text or "").split())
    return flattened[:limit]


def _is_provable(finding: Finding) -> bool:
    haystack = f"{finding.title} {finding.cwe} {finding.hypothesis}".lower()
    return any(hint in haystack for hint in _PROVABLE_HINTS)


def _sandbox_env() -> dict[str, str]:
    env = {k: os.environ[k] for k in _ENV_KEEP if k in os.environ}
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # Belt and braces alongside -I: neutralise inherited import paths.
    env["PYTHONPATH"] = ""
    env["PYTHONNOUSERSITE"] = "1"
    env["NO_PROXY"] = "*"
    return env


def _execute(script: str, timeout: int) -> tuple[str, str]:
    """Run a script in a disposable sandbox. Returns (state, detail)."""
    workdir = tempfile.mkdtemp(prefix="mdash-prove-")
    path = Path(workdir) / "poc.py"
    try:
        path.write_text(_NETWORK_GUARD + script, encoding="utf-8")
        try:
            proc = subprocess.run(
                [sys.executable, "-I", "-S", str(path)],
                cwd=workdir,
                env=_sandbox_env(),
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
                check=False,
            )
        except subprocess.TimeoutExpired:
            # A hang is itself meaningful for ReDoS and entity expansion, but it is not a
            # clean demonstration, so it does not count as proven.
            return ProofState.INCONCLUSIVE.value, f"PoC exceeded {timeout}s wall clock (possible DoS)"
        except OSError as exc:
            return ProofState.INCONCLUSIVE.value, f"PoC could not be executed: {exc}"

        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        if "VULNERABLE" in stdout:
            return ProofState.PROVEN.value, f"PoC printed VULNERABLE\n{stdout[:900]}"
        if "SAFE" in stdout:
            return ProofState.DISPROVEN.value, f"PoC printed SAFE\n{stdout[:900]}"
        detail = f"exit={proc.returncode}\nstdout: {stdout[:500]}\nstderr: {stderr[:500]}"
        return ProofState.INCONCLUSIVE.value, detail
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


async def run(
    panel: Panel,
    cfg: Config,
    findings: list[Finding],
    sources: dict[str, str],
) -> list[Finding]:
    """Attempt proofs for the eligible findings. Never removes findings."""
    eligible = [f for f in findings if _is_provable(f) and severity_rank(f.severity) >= 2]
    if not eligible:
        log.info("Prove: no findings in a mechanically provable class")
        return findings
    log.info("Prove: attempting %d proof(s) - EXECUTES GENERATED CODE", len(eligible))

    async def prove_one(finding: Finding) -> None:
        source = sources.get(finding.path, "")
        lines = source.splitlines()
        start = max(0, finding.line_start - 30)
        end = min(len(lines), finding.line_end + 30)
        excerpt = "\n".join(lines[start:end])
        prompt = (
            f"## Finding\n{finding.title}\n"
            f"CWE: {finding.cwe or 'unspecified'} | File: {finding.path}\n\n"
            f"### Mechanism\n{finding.hypothesis}\n\n"
            f"### Vulnerable code\n```python\n{excerpt}\n```\n\n"
            "Write the proof-of-concept, or reply NOT_PROVABLE."
        )
        try:
            raw, _ = await panel.complete("escalation", PROVER_SYSTEM, prompt, as_json=False)
        except Exception as exc:  # noqa: BLE001
            log.warning("prover failed for %s: %s", _sanitise_for_log(finding.title, 60), exc)
            return

        script = raw.strip()
        if script.startswith("```"):
            script = script.strip("`")
            if script.lower().startswith("python"):
                script = script[6:]
            script = script.strip()
        if not script or "NOT_PROVABLE" in script[:200]:
            finding.proof_state = ProofState.NOT_ATTEMPTED
            finding.proof_detail = "Model judged the mechanism not demonstrable in isolation."
            return
        if len(script.encode("utf-8")) > _MAX_SCRIPT_BYTES:
            finding.proof_state = ProofState.INCONCLUSIVE
            finding.proof_detail = "Generated PoC exceeded the size limit."
            return

        state, detail = await asyncio.to_thread(_execute, script, cfg.prove_timeout)
        finding.proof_state = ProofState(state)
        finding.proof_detail = detail
        if finding.proof_state is ProofState.PROVEN:
            # An executed demonstration outweighs any amount of argument.
            finding.confidence = max(finding.confidence, 0.95)
            log.info("  PROVEN: %s (%s)", _sanitise_for_log(finding.title, 70), finding.path)
        elif finding.proof_state is ProofState.DISPROVEN:
            finding.confidence = min(finding.confidence, 0.30)
            log.info("  disproven: %s (%s)", _sanitise_for_log(finding.title, 70), finding.path)

    await asyncio.gather(*(prove_one(f) for f in eligible))
    proven = sum(1 for f in eligible if f.proof_state is ProofState.PROVEN)
    log.info("Prove complete: %d proven, %d attempted", proven, len(eligible))
    return findings
