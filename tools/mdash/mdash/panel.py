"""Azure AI Foundry client and the cost-tiered model router.

Three things here are load-bearing.

**Independence.** The debate stage must not be judged by the same model that produced the
finding - a model asked to review its own output largely agrees with itself. `Panel.complete`
takes a role, and the roles are wired to different deployments precisely so the counterpoint
is genuinely independent.

**Cost tiering.** The published MDASH economics come from routing the high-volume passes to a
cheap model and reserving the expensive reasoner for the minority of hard cases. Here the
cheap seat handles every debate, and `escalation` is only reached when auditor and debater
disagree - so spend tracks difficulty rather than repository size.

**The Responses API, not Chat Completions.** This is a hard requirement, not a preference:
reasoning deployments such as `gpt-5.3-codex` report ``chatCompletion: false`` and serve only
``/responses``. Responses is also the only surface here that accepts a strict ``json_schema``,
which turns "please reply with JSON" from a prompt-time wish into a service-side guarantee.

Auth is Entra-first (`DefaultAzureCredential`): `az login` locally, federated OIDC in CI, no
stored key. An API key is honoured only if explicitly provided via AZURE_OPENAI_API_KEY.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from openai import APIConnectionError, APIStatusError, AsyncAzureOpenAI, RateLimitError

from .config import Config, RoleConfig

log = logging.getLogger("mdash.panel")

_SCOPE = "https://cognitiveservices.azure.com/.default"
# Fenced JSON, optionally language-tagged, is the most common way a model wraps structured
# output. Strict schemas make this rare, but a schema is not always in play.
_FENCE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)

# A Foundry account exposes several hostnames for the same resource, and only the OpenAI one
# routes /responses - the multi-service host answers 404. Rewriting is friendlier than making
# every user discover that from a bare 404.
_HOST_REWRITES = (".cognitiveservices.azure.com", ".services.ai.azure.com")
_OPENAI_HOST = ".openai.azure.com"


@dataclass
class Usage:
    """Token accounting, kept per deployment so the cost story is inspectable."""

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0

    def add(self, prompt: int, completion: int, reasoning: int = 0) -> None:
        self.calls += 1
        self.input_tokens += prompt
        self.output_tokens += completion
        self.reasoning_tokens += reasoning


def normalise_endpoint(endpoint: str) -> str:
    """Point any Foundry hostname for a resource at the OpenAI host that serves /responses."""
    parts = urlsplit(endpoint if "://" in endpoint else f"https://{endpoint}")
    host = parts.netloc
    for suffix in _HOST_REWRITES:
        if host.endswith(suffix):
            host = host[: -len(suffix)] + _OPENAI_HOST
            log.debug("Rewrote endpoint host to %s for the Responses API", host)
            break
    return urlunsplit((parts.scheme or "https", host, parts.path or "/", "", ""))


def extract_json(text: str) -> Any:
    """Best-effort structured parse of a model response.

    Tries the raw text, then a fenced block, then the outermost balanced ``[...]``/``{...}``.
    Returns None rather than raising: one malformed agent response should degrade that agent's
    contribution, not abort a scan that may have already cost real money.
    """
    if not text:
        return None
    for candidate in _json_candidates(text):
        try:
            return json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
    return None


def _json_candidates(text: str) -> list[str]:
    out = [text.strip()]
    fenced = _FENCE.search(text)
    if fenced:
        out.append(fenced.group(1).strip())
    for opener, closer in (("[", "]"), ("{", "}")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end > start:
            out.append(text[start : end + 1])
    return out


class Panel:
    """Holds one Foundry client and dispatches to the configured role deployments."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.usage: dict[str, Usage] = {}
        self._sem = asyncio.Semaphore(max(1, cfg.concurrency))
        self._client = self._build_client(cfg)
        # Not every deployment accepts every knob. Rejections are learned from the error body
        # once per deployment and then respected, so a mixed panel degrades instead of failing.
        self._quirks: dict[str, set[str]] = {}

    @staticmethod
    def _build_client(cfg: Config) -> AsyncAzureOpenAI:
        endpoint = cfg.endpoint or os.environ.get("AZURE_OPENAI_ENDPOINT", "")
        if not endpoint:
            raise RuntimeError(
                "No Foundry endpoint. Set AZURE_OPENAI_ENDPOINT or panel.endpoint in mdash.toml."
            )
        endpoint = normalise_endpoint(endpoint)
        api_version = cfg.api_version
        api_key = os.environ.get("AZURE_OPENAI_API_KEY", "").strip()
        if api_key:
            log.warning("Using AZURE_OPENAI_API_KEY; prefer Entra credentials where possible.")
            return AsyncAzureOpenAI(
                azure_endpoint=endpoint, api_version=api_version, api_key=api_key
            )

        from azure.identity import DefaultAzureCredential, get_bearer_token_provider

        provider = get_bearer_token_provider(DefaultAzureCredential(), _SCOPE)
        return AsyncAzureOpenAI(
            azure_endpoint=endpoint,
            api_version=api_version,
            azure_ad_token_provider=provider,
        )

    async def complete(
        self,
        role: str,
        system: str,
        user: str,
        *,
        as_json: bool = True,
        schema: dict[str, Any] | None = None,
    ) -> tuple[str, Any]:
        """Run one turn on `role`'s deployment. Returns (raw_text, parsed_json|None).

        `schema` requests service-side structured output. The result is still parsed
        defensively, because a response truncated by the output-token cap is valid JSON
        to nobody.
        """
        spec = self.cfg.role(role)
        async with self._sem:
            text = await self._call_with_retry(spec, system, user, schema if as_json else None)
        return text, (extract_json(text) if as_json else None)

    async def _call_with_retry(
        self, spec: RoleConfig, system: str, user: str, schema: dict[str, Any] | None
    ) -> str:
        delay = 2.0
        last: Exception | None = None
        for attempt in range(1, self.cfg.max_retries + 1):
            try:
                return await self._call(spec, system, user, schema)
            except RateLimitError as exc:
                last = exc
                # Honour Retry-After when the service supplies it.
                wait = _retry_after(exc) or delay
                log.warning(
                    "%s rate limited (attempt %d/%d), retrying in %.0fs",
                    spec.deployment,
                    attempt,
                    self.cfg.max_retries,
                    wait,
                )
                await asyncio.sleep(wait)
                delay = min(delay * 2, 60)
            except APIConnectionError as exc:
                last = exc
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30)
            except APIStatusError as exc:
                if exc.status_code and 400 <= exc.status_code < 500 and exc.status_code != 429:
                    raise
                last = exc
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30)
        raise RuntimeError(f"{spec.deployment}: exhausted retries") from last

    def _kwargs(
        self, spec: RoleConfig, system: str, user: str, schema: dict[str, Any] | None
    ) -> dict[str, Any]:
        quirks = self._quirks.setdefault(spec.deployment, set())
        kwargs: dict[str, Any] = {
            "model": spec.deployment,
            "instructions": system,
            "input": user,
            "max_output_tokens": spec.max_output_tokens,
            # Source code is the input here. Do not leave it in server-side response state.
            "store": False,
        }
        if spec.temperature is not None and "no_temperature" not in quirks:
            kwargs["temperature"] = spec.temperature
        if spec.reasoning_effort and "no_reasoning" not in quirks:
            kwargs["reasoning"] = {"effort": spec.reasoning_effort}
        if schema and "no_schema" not in quirks:
            kwargs["text"] = {
                "format": {
                    "type": "json_schema",
                    "name": "mdash_response",
                    "strict": True,
                    "schema": schema,
                }
            }
        return kwargs

    async def _call(
        self, spec: RoleConfig, system: str, user: str, schema: dict[str, Any] | None
    ) -> str:
        quirks = self._quirks.setdefault(spec.deployment, set())
        try:
            resp = await self._client.responses.create(
                timeout=self.cfg.request_timeout, **self._kwargs(spec, system, user, schema)
            )
        except APIStatusError as exc:
            # Learn an unsupported knob from the error body, record it for this deployment,
            # and retry once. Losing structured output is survivable; failing the scan is not.
            body = str(getattr(exc, "message", "") or exc).lower()
            for token, quirk in (
                ("temperature", "no_temperature"),
                ("reasoning", "no_reasoning"),
                ("json_schema", "no_schema"),
                ("schema", "no_schema"),
            ):
                if token in body and quirk not in quirks:
                    quirks.add(quirk)
                    log.warning("%s rejected '%s'; retrying without it", spec.deployment, token)
                    return await self._call(spec, system, user, schema)
            raise

        self._record(spec.deployment, resp)
        if getattr(resp, "status", None) == "incomplete":
            reason = getattr(getattr(resp, "incomplete_details", None), "reason", "unknown")
            log.warning(
                "%s response incomplete (%s); consider raising max_output_tokens",
                spec.deployment,
                reason,
            )
        return resp.output_text or ""

    def _record(self, deployment: str, resp: Any) -> None:
        usage = self.usage.setdefault(deployment, Usage())
        raw = getattr(resp, "usage", None)
        if not raw:
            usage.calls += 1
            return
        details = getattr(raw, "output_tokens_details", None)
        usage.add(
            getattr(raw, "input_tokens", 0) or 0,
            getattr(raw, "output_tokens", 0) or 0,
            (getattr(details, "reasoning_tokens", 0) or 0) if details else 0,
        )

    def usage_summary(self) -> dict[str, dict[str, int]]:
        return {
            dep: {
                "calls": u.calls,
                "input_tokens": u.input_tokens,
                "output_tokens": u.output_tokens,
                "reasoning_tokens": u.reasoning_tokens,
            }
            for dep, u in sorted(self.usage.items())
        }

    async def aclose(self) -> None:
        await self._client.close()


def _retry_after(exc: Exception) -> float | None:
    headers = getattr(getattr(exc, "response", None), "headers", None)
    if not headers:
        return None
    raw = headers.get("retry-after") or headers.get("Retry-After")
    try:
        return float(raw) if raw else None
    except (TypeError, ValueError):
        return None
