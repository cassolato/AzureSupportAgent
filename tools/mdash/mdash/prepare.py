"""Prepare stage: ingest the source tree and draw the attack surface.

MDASH's prepare stage "ingests the source target, builds language-aware indices, and then
draws the attack surface and threat models by analyzing the past commits". The intent is
targeting: an LLM pass over every file in a large repository is neither affordable nor
useful, and reviewing a data class costs the same as reviewing an authentication path.

Targets are therefore ranked by three independent signals and the budget is spent top-down:

1. **Path affinity** - directories whose names carry security meaning (auth, exec, api).
2. **Content markers** - the code actually performs risky operations (subprocess, raw SQL,
   deserialization, outbound HTTP, credential handling).
3. **Churn** - files changed recently. Recently modified code is where regressions live, and
   it is also the code a reviewer has the most leverage over.
"""
from __future__ import annotations

import fnmatch
import logging
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("mdash.prepare")

_DEFAULT_EXCLUDES = (
    "**/.git/**", "**/node_modules/**", "**/.venv*/**", "**/venv/**", "**/dist/**",
    "**/build/**", "**/__pycache__/**", "**/*.min.js", "**/third_party/**",
    "**/site-packages/**", "**/.mypy_cache/**", "**/.ruff_cache/**", "**/.pytest_cache/**",
)

# Path fragment -> weight. Deliberately coarse; this only has to order the queue.
_PATH_WEIGHTS = {
    "auth": 5.0, "security": 4.5, "crypto": 4.5, "exec": 4.5, "command": 4.0,
    "session": 3.5, "token": 3.5, "credential": 4.0, "secret": 4.0, "password": 4.0,
    "api/": 3.0, "router": 2.5, "connector": 3.0, "webhook": 3.0, "upload": 3.0,
    "admin": 3.0, "rbac": 3.5, "permission": 3.0, "saml": 4.5, "oidc": 4.5, "sso": 4.0,
    "middleware": 2.5, "agent": 2.5, "tool": 2.0, "mcp": 2.5, "proxy": 2.5,
    "dockerfile": 3.0, "docker-compose": 3.0, "deploy": 2.5, "workflow": 2.5, "bicep": 2.5,
    "ssh": 3.5, "ssrf": 4.0, "sanitiz": 3.0, "valid": 2.0, "parse": 2.0,
}

# Regex -> weight for risky operations that are visible in the source text.
_CONTENT_MARKERS: tuple[tuple[re.Pattern[str], float], ...] = (
    (re.compile(r"\bsubprocess\.|\bos\.system\b|\bshell\s*=\s*True"), 4.0),
    (re.compile(r"\beval\s*\(|\bexec\s*\(|\bpickle\.loads?\b|yaml\.load\s*\("), 5.0),
    (re.compile(r"\bhttpx\.|\brequests\.|\baiohttp\.|\burlopen\b|fetch\s*\("), 2.5),
    (re.compile(r"\bexecute\s*\(\s*f?[\"']|text\s*\(\s*f[\"']|\braw_sql\b"), 3.5),
    (re.compile(r"\bfromstring\b|etree\.|xml\.|BeautifulSoup"), 3.0),
    (re.compile(r"\bjwt\.|\bdecode\s*\(|verify_signature|algorithms\s*="), 3.5),
    (re.compile(r"password|secret|api_key|client_secret|token", re.IGNORECASE), 2.0),
    (re.compile(r"\bhashlib\.|\bFernet\b|\bAES\b|\bcipher\b", re.IGNORECASE), 2.5),
    (re.compile(r"@(app|router)\.(get|post|put|delete|patch)"), 2.5),
    (re.compile(r"\bDepends\s*\(|current_user|require_|authorize"), 2.5),
    (re.compile(r"USER\s+root|FROM\s+\w+:latest|npm\s+install\b|--privileged"), 3.0),
    (re.compile(r"0\.0\.0\.0|publicNetworkAccess|allowAll|AllowAzureServices"), 2.5),
)


@dataclass
class Target:
    """One reviewable unit handed to the scan stage."""

    path: str
    text: str
    score: float
    reasons: list[str]
    line_count: int

    def numbered(self, *, max_chars: int) -> str:
        """Render with line numbers so findings can cite real locations.

        Truncation is by whole lines and is announced in-band, so a model never silently
        reasons about a file it only partly received.
        """
        lines = self.text.splitlines()
        out: list[str] = []
        used = 0
        for idx, line in enumerate(lines, start=1):
            row = f"{idx:5d} | {line}"
            if used + len(row) > max_chars:
                remaining = len(lines) - idx + 1
                out.append(f"... [truncated: {remaining} further lines not shown] ...")
                break
            out.append(row)
            used += len(row) + 1
        return "\n".join(out)


def _matches_any(rel: str, patterns: tuple[str, ...] | list[str]) -> bool:
    posix = rel.replace("\\", "/")
    for pat in patterns:
        if fnmatch.fnmatch(posix, pat):
            return True
        # fnmatch knows nothing about path segments, so "**/node_modules/**" demands at least
        # one character before the slash and therefore never matches a top-level
        # "node_modules/...". Retrying without the leading "**/" restores the intended
        # "at any depth, including the repository root" meaning.
        if pat.startswith("**/") and fnmatch.fnmatch(posix, pat[3:]):
            return True
    return False


def _churn(root: Path, *, days: int = 180) -> Counter[str]:
    """Commit counts per file over a recent window, via git. Empty if git is unavailable."""
    counts: Counter[str] = Counter()
    try:
        proc = subprocess.run(
            ["git", "log", f"--since={days}.days", "--name-only", "--pretty=format:"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("git churn unavailable: %s", exc)
        return counts
    if proc.returncode != 0:
        return counts
    for line in proc.stdout.splitlines():
        name = line.strip()
        if name:
            counts[name] += 1
    return counts


def _score(rel: str, text: str, churn: Counter[str]) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []
    lowered = rel.replace("\\", "/").lower()

    hits = [(frag, w) for frag, w in _PATH_WEIGHTS.items() if frag in lowered]
    if hits:
        # Only the strongest path signal counts. Summing lets a long path outrank a genuinely
        # sensitive short one purely by accumulating weak matches.
        frag, weight = max(hits, key=lambda kv: kv[1])
        score += weight
        reasons.append(f"path:{frag}")

    for pattern, weight in _CONTENT_MARKERS:
        if pattern.search(text):
            score += weight
            reasons.append(f"marker:{pattern.pattern[:28]}")

    commits = churn.get(rel.replace("\\", "/"), 0)
    if commits:
        # Diminishing returns: 20 commits should not outweigh every content signal.
        bonus = min(4.0, 1.5 * (commits ** 0.5))
        score += bonus
        reasons.append(f"churn:{commits}")

    return score, reasons


def collect(
    root: Path,
    *,
    include: list[str],
    exclude: list[str],
    max_targets: int,
    max_file_bytes: int,
    paths: list[str] | None = None,
) -> list[Target]:
    """Build the ranked target queue.

    `paths` restricts the scan to an explicit set (used for pull-request diffs), in which
    case ranking still applies but the include globs do not.
    """
    excludes = tuple(_DEFAULT_EXCLUDES) + tuple(exclude)
    churn = _churn(root)
    candidates: list[Path] = []

    if paths:
        for raw in paths:
            candidate = (root / raw).resolve()
            # Containment check: a diff-supplied path must not escape the repo root.
            if candidate.is_file() and candidate.is_relative_to(root.resolve()):
                candidates.append(candidate)
    else:
        seen: set[Path] = set()
        for pattern in include:
            for match in root.glob(pattern):
                if match.is_file() and match not in seen:
                    seen.add(match)
                    candidates.append(match)

    targets: list[Target] = []
    explicit = bool(paths)
    for file in candidates:
        rel = str(file.relative_to(root)).replace("\\", "/")
        if _matches_any(rel, excludes):
            continue
        try:
            if file.stat().st_size > max_file_bytes:
                continue
            text = file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if not text.strip():
            continue
        score, reasons = _score(rel, text, churn)
        if score <= 0 and not explicit:
            # In a whole-repo sweep the score floor rations a finite budget. With an explicit
            # path list (a pull-request diff) the caller has already chosen the files, so the
            # score only orders them - dropping one would skip a vulnerability newly
            # introduced into a file that carries no pre-existing security markers.
            continue
        targets.append(
            Target(
                path=rel,
                text=text,
                score=score,
                reasons=reasons,
                line_count=text.count("\n") + 1,
            )
        )

    targets.sort(key=lambda t: (-t.score, t.path))
    if len(targets) > max_targets:
        log.info("Attack surface: %d candidates, scanning top %d", len(targets), max_targets)
        targets = targets[:max_targets]
    return targets
