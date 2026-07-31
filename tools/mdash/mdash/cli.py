"""Command-line entry point: wires the five stages together.

Pipeline, mirroring the published MDASH stage design:

    prepare -> scan -> validate (debate, with escalation) -> dedupe -> prove -> report

Every stage is optional except prepare and scan, so the harness degrades to a plain agentic
scanner when the budget is tight, and each stage's output is written to disk for inspection.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

from . import agents as agent_defs
from . import dedupe as dedupe_stage
from . import prepare as prepare_stage
from . import prove as prove_stage
from . import sarif as sarif_out
from . import scan as scan_stage
from . import validate as validate_stage
from .config import Config
from .findings import Finding, ProofState, severity_rank
from .panel import Panel

log = logging.getLogger("mdash")

_EXIT_OK = 0
_EXIT_FINDINGS = 1
_EXIT_ERROR = 2


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mdash",
        description="Multi-model agentic security scanning harness for this repository.",
    )
    p.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root to scan.")
    p.add_argument("--config", type=Path, default=None, help="Path to mdash.toml.")
    p.add_argument("--out", type=Path, default=Path("mdash-results"), help="Output directory.")
    p.add_argument(
        "--agents",
        default="",
        help=f"Comma-separated subset of: {','.join(a.name for a in agent_defs.ALL_AGENTS)}",
    )
    p.add_argument("--max-targets", type=int, default=None, help="Cap on files scanned.")
    p.add_argument("--concurrency", type=int, default=None, help="Parallel model requests.")
    p.add_argument("--endpoint", default=None, help="Azure AI Foundry endpoint URL.")
    p.add_argument(
        "--diff",
        metavar="BASE_REF",
        default=None,
        help="Scan only files changed against BASE_REF (pull-request mode).",
    )
    p.add_argument("--no-debate", action="store_true", help="Skip the adversarial debate stage.")
    p.add_argument(
        "--prove",
        action="store_true",
        help="Enable the prove stage. EXECUTES MODEL-GENERATED CODE - use in CI or a container.",
    )
    p.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info", "never"],
        default="high",
        help="Exit non-zero when a finding at or above this severity survives.",
    )
    p.add_argument("--verbose", "-v", action="store_true")
    return p


def _changed_files(root: Path, base_ref: str) -> list[str]:
    """Files changed against a base ref, for pull-request scans."""
    try:
        proc = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=d", f"{base_ref}...HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.error("Could not compute diff against %s: %s", base_ref, exc)
        return []
    if proc.returncode != 0:
        log.error("git diff failed: %s", (proc.stderr or "").strip()[:300])
        return []
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _summary(findings: list[Finding], usage: dict[str, object]) -> str:
    """Markdown digest, suitable for a GitHub Actions job summary."""
    if not findings:
        body = "No findings survived adversarial review.\n"
    else:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        tally = " · ".join(
            f"**{counts[s]}** {s}" for s in ("critical", "high", "medium", "low", "info") if s in counts
        )
        rows = [
            "| Severity | Finding | Location | CWE | Confidence | Proof |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for f in findings[:60]:
            proof = {
                ProofState.PROVEN: "✅ proven",
                ProofState.DISPROVEN: "❌ disproven",
                ProofState.INCONCLUSIVE: "· inconclusive",
                ProofState.NOT_ATTEMPTED: "—",
            }[f.proof_state]
            loc = f"`{f.path}:{f.line_start}`" if f.line_start else f"`{f.path}`"
            star = " ⭐" if f.corroborations else ""
            rows.append(
                f"| {f.severity} | {f.title[:96]}{star} | {loc} | {f.cwe or '—'} "
                f"| {f.confidence:.2f} | {proof} |"
            )
        body = f"{tally}\n\n" + "\n".join(rows) + "\n\n⭐ = independently corroborated by a second agent.\n"

    spend = "\n".join(
        f"- `{dep}`: {u['calls']} calls, {u['input_tokens']:,} in / {u['output_tokens']:,} out"
        for dep, u in usage.items()  # type: ignore[union-attr]
    )
    return f"## Agentic security scan\n\n{body}\n### Model panel usage\n{spend or '- (none)'}\n"


async def _run(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    if not root.is_dir():
        log.error("Root is not a directory: %s", root)
        return _EXIT_ERROR

    cfg = Config.load(args.config, root=root)
    if args.endpoint:
        cfg.endpoint = args.endpoint
    if args.max_targets is not None:
        cfg.max_targets = args.max_targets
    if args.concurrency is not None:
        cfg.concurrency = args.concurrency
    if args.no_debate:
        cfg.debate = False
    if args.prove:
        cfg.prove = True
    selected = agent_defs.select(
        [a.strip() for a in args.agents.split(",") if a.strip()] or cfg.agents
    )

    paths = _changed_files(root, args.diff) if args.diff else None
    if args.diff is not None and not paths:
        log.info("No changed files against %s - nothing to scan.", args.diff)
        args.out.mkdir(parents=True, exist_ok=True)
        sarif_out.write([], args.out / "mdash.sarif")
        return _EXIT_OK

    targets = prepare_stage.collect(
        root,
        include=cfg.include,
        exclude=cfg.exclude,
        max_targets=cfg.max_targets,
        max_file_bytes=cfg.max_file_bytes,
        paths=paths,
    )
    if not targets:
        log.warning("Prepare produced no targets - check scope.include in mdash.toml.")
        args.out.mkdir(parents=True, exist_ok=True)
        sarif_out.write([], args.out / "mdash.sarif")
        return _EXIT_OK

    log.info(
        "Prepare: %d target(s); panel = auditor:%s debater:%s escalation:%s",
        len(targets),
        cfg.auditor.deployment,
        cfg.debater.deployment,
        cfg.escalation.deployment,
    )
    sources = {t.path: t.text for t in targets}

    panel = Panel(cfg)
    try:
        findings = await scan_stage.run(panel, cfg, targets, selected)
        if cfg.debate:
            findings = await validate_stage.run(panel, cfg, findings, sources)
        findings = dedupe_stage.run(findings)
        if cfg.prove:
            findings = await prove_stage.run(panel, cfg, findings, sources)
        usage = panel.usage_summary()
    finally:
        await panel.aclose()

    findings.sort(key=lambda f: (-severity_rank(f.severity), -f.confidence, f.path))

    _emit(findings, usage, args.out)

    if args.fail_on != "never":
        threshold = severity_rank(args.fail_on)
        blocking = [f for f in findings if severity_rank(f.severity) >= threshold]
        if blocking:
            log.error("%d finding(s) at or above '%s'", len(blocking), args.fail_on)
            return _EXIT_FINDINGS
    return _EXIT_OK


def _emit(findings: list[Finding], usage: dict[str, dict[str, int]], out: Path) -> None:
    """Write every report artefact. Kept synchronous so the file I/O never blocks a loop."""
    out.mkdir(parents=True, exist_ok=True)
    sarif_out.write(findings, out / "mdash.sarif", usage=usage)
    (out / "findings.json").write_text(
        json.dumps({"findings": [f.to_dict() for f in findings], "usage": usage}, indent=2),
        encoding="utf-8",
    )
    summary = _summary(findings, usage)
    (out / "summary.md").write_text(summary, encoding="utf-8")

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(summary)

    try:
        print(summary)
    except UnicodeEncodeError:
        # A legacy console encoding must never discard a scan that has already been paid
        # for. The artefacts on disk are the real output; stdout is a convenience.
        print(summary.encode("ascii", "replace").decode("ascii"))
    log.info("Wrote %s", out / "mdash.sarif")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    # The report contains non-ASCII marks and findings quote arbitrary source. A console that
    # cannot encode one character must not discard a scan that has already been paid for.
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, ValueError, OSError):
            stream.reconfigure(encoding="utf-8", errors="replace")
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(name)-16s %(message)s",
        stream=sys.stderr,
    )
    try:
        return asyncio.run(_run(args))
    except KeyboardInterrupt:
        return _EXIT_ERROR
    except (RuntimeError, ValueError, FileNotFoundError) as exc:
        log.error("%s", exc)
        return _EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
