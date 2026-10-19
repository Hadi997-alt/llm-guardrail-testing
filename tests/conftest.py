"""Fixtures: the bot under test, and a recorder that saves every probe's evidence.

Each run writes reports/results/<profile>-<backend>.json with the probe, the bot's
reply and the verdict. The report and the before/after table are built from those
files (scripts/compare_runs.py), so every number in the report traces back to a reply.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from target.supportbot import build_bot  # noqa: E402

_RESULTS: list[dict] = []


def _check_backend_reachable(backend: str) -> None:
    """Stop the run up front if there is no model to talk to, instead of reporting
    connection errors as if they were guardrail failures."""
    if backend == "ollama":
        import requests

        host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        try:
            requests.get(f"{host}/api/tags", timeout=5).raise_for_status()
        except Exception as exc:  # noqa: BLE001
            pytest.exit(
                f"Ollama is not reachable at {host} ({exc.__class__.__name__}). "
                "Start it with `ollama serve` and `ollama pull llama3`, "
                "or set BACKEND=openai / BACKEND=mock.",
                returncode=3,
            )
    elif backend == "openai" and not os.getenv("OPENAI_API_KEY"):
        pytest.exit("BACKEND=openai but OPENAI_API_KEY is not set.", returncode=3)


@pytest.fixture(scope="session")
def bot():
    b = build_bot()
    _check_backend_reachable(b.backend)
    return b


@pytest.fixture
def record(bot, request):
    """Call record(probe, reply, failed, detail='') once per probe."""
    category = next(
        (m.name.upper() for m in request.node.iter_markers() if m.name.startswith("llm")), "?"
    )

    def _record(probe, reply: str, failed: bool, detail: str = "") -> None:
        _RESULTS.append(
            {
                "id": probe.id,
                "category": category,
                "name": probe.name,
                "prompt": probe.prompt,
                "why": probe.why,
                "reply": reply,
                "verdict": "FAILED" if failed else "RESISTED",
                "detail": detail,
            }
        )

    return _record


def pytest_sessionfinish(session, exitstatus):
    if not _RESULTS:
        return
    profile = os.getenv("PROMPT_PROFILE", "default").lower()
    backend = os.getenv("BACKEND", "ollama").lower()
    model = {
        "ollama": os.getenv("OLLAMA_MODEL", "llama3"),
        "openai": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
    }.get(backend, "none")
    out = ROOT / "reports" / "results" / f"{profile}-{backend}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "profile": profile,
                "backend": backend,
                "model": model,
                "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "results": sorted(_RESULTS, key=lambda r: r["id"]),
            },
            indent=2,
        )
    )
