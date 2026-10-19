"""Scan the default and hardened bots with Garak, then write reports/report.md.

Pipeline: scanning/run_garak.py (Garak probes -> raw JSONL)
       -> analysis/parse_results.py (findings + hit rates + evidence)
       -> analysis/severity.py (Critical/High/Medium/Low)
       -> this file (findings table, OWASP coverage matrix, before-vs-after, chart)

    python -m report.generate_report                 # scan both profiles, then report
    python -m report.generate_report --skip-scan     # rebuild from existing raw reports

Evidence is written inside inline code spans. Garak's LLM05 probes try to make the bot
emit markdown images and HTML; pasting those replies into the report as-is would make
the report itself render them (improper output handling in our own deliverable).

BACKEND=mock runs are written to reports/report-mock.md: they prove the pipeline works
and say nothing about any model.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analysis import parse_results, severity  # noqa: E402
from analysis.owasp_mapping import CURATED_PROBES, OWASP_CATEGORIES, TESTED_CATEGORIES  # noqa: E402

REPORTS = ROOT / "reports"

REMEDIATION = {
    "LLM01": "Treat user text and retrieved content as data: delimit it, restate rule priority, and never let model output trigger actions without a check outside the model.",
    "LLM02": "Keep secrets out of the model's context entirely (look them up server-side after an authorisation check); add an output filter as a backstop.",
    "LLM05": "Encode or sanitise model output for the place it is rendered (HTML-escape, block remote markdown images, strip terminal escape codes).",
    "LLM07": "Assume the system prompt will leak: put nothing in it that is secret, and enforce rules in code rather than in prompt text.",
    "LLM09": "Ground answers in a fixed fact source, tell the model to say 'I don't know', and verify package names or citations before showing them.",
}


def hardened_available() -> bool:
    return importlib.util.find_spec("harden.hardened_bot") is not None


def scan(profiles: list[str], backend: str, generations: int, cap: int) -> None:
    from scanning.run_garak import run_probe

    for profile in profiles:
        for m in CURATED_PROBES:
            run_probe(m.probe, profile, backend, generations, cap)


def analyse(profile: str, backend: str) -> list:
    findings = severity.rate(parse_results.parse_run(profile, backend))
    if findings:
        parse_results.save(findings, profile, backend)
    return findings


# --------------------------------------------------------------------------- helpers


def code(text: str, limit: int = 160) -> str:
    """Render untrusted text inertly inside a markdown table cell."""
    text = " ".join((text or "").split())
    if len(text) > limit:
        text = text[:limit] + " ..."
    text = text.replace("`", "'").replace("|", "\\|")
    return f"`{text}`" if text else ""


def by_category(findings: list) -> dict[str, tuple[int, int]]:
    """{category: (fails, total)} summed over Garak's own detectors.

    The SupportBot token/canary re-checks are reported separately: they re-score the
    same replies, so adding them here would count those replies twice."""
    out: dict[str, list[int]] = {}
    for f in findings:
        if f.detector.startswith("supportbot."):
            continue
        cur = out.setdefault(f.category, [0, 0])
        cur[0] += f.failed
        cur[1] += f.total
    return {k: (v[0], v[1]) for k, v in out.items()}


def pct(fails: int, total: int) -> str:
    return f"{fails}/{total} ({fails / total:.0%})" if total else "n/a"


def worst(findings: list, cat: str) -> str:
    sevs = [f.severity for f in findings if f.category == cat and f.failed]
    return max(sevs, key=lambda s: severity.ORDER[s]) if sevs else "None"


def sample_probe_summary(profile: str, backend: str) -> str:
    path = REPORTS / "results" / f"{profile}-{backend}.json"
    if not path.exists():
        return "Not run yet for this backend: `pytest tests/ -v`."
    results = json.loads(path.read_text())["results"]
    failed = [r for r in results if r["verdict"] == "FAILED"]
    lines = [f"{len(results) - len(failed)}/{len(results)} resisted."]
    lines += [f"- {r['id']} {r['name']}: failed" for r in failed]
    return "\n".join(lines)


def chart(before: dict, after: dict, path: Path) -> bool:
    """Grouped bar chart of hit rate by category, default vs hardened."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return False
    cats = [c for c in TESTED_CATEGORIES if c in before or c in after]
    rate = lambda d, c: (d[c][0] / d[c][1] * 100) if c in d and d[c][1] else 0  # noqa: E731
    xs = range(len(cats))
    width = 0.38
    fig, ax = plt.subplots(figsize=(7, 3.6), dpi=150)
    fig.patch.set_facecolor("#fcfcfb")
    ax.set_facecolor("#fcfcfb")
    ax.bar([x - width / 2 - 0.01 for x in xs], [rate(before, c) for c in cats], width, label="Default bot", color="#2a78d6")
    ax.bar([x + width / 2 + 0.01 for x in xs], [rate(after, c) for c in cats], width, label="Hardened bot", color="#eb6834")
    ax.set_xticks(list(xs), [f"{c}\n{OWASP_CATEGORIES[c]['name']}" for c in cats], fontsize=7, color="#52514e")
    ax.set_ylabel("Probe hit rate (%)", fontsize=8, color="#52514e")
    ax.set_ylim(0, 100)
    ax.set_title("Garak hit rate by OWASP category", fontsize=10, color="#0b0b0b", loc="left")
    ax.grid(axis="y", color="#e5e4e0", linewidth=0.6)
    ax.set_axisbelow(True)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color("#c3c2b7")
    ax.tick_params(axis="y", labelsize=7, colors="#52514e", length=0)
    ax.tick_params(axis="x", length=0)
    ax.legend(frameon=False, fontsize=8, loc="lower right", bbox_to_anchor=(1, 1.0), ncol=2)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    return True


# --------------------------------------------------------------------------- report


def build(backend: str, default: list, hardened: list | None) -> str:
    model = {"ollama": os.getenv("OLLAMA_MODEL", "llama3"), "openai": os.getenv("OPENAI_MODEL", "gpt-4o-mini")}.get(backend, "none")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = ["# Guardrail robustness report: SupportBot", ""]
    out += [f"Target: SupportBot (local, defined in `target/supportbot.py`) · Backend: `{backend}` · Model: `{model}` · Generated: {now}", ""]
    if backend == "mock":
        out += ["> **Pipeline smoke test.** The mock backend has no model behind it; it is a scripted bot that obeys every instruction. These numbers only show that the scan, parsing, severity and report steps work end to end.", ""]

    if not default:
        out += [
            "## Status: pending a real run",
            "",
            "No Garak results for this backend yet. Findings, evidence, severity ratings and the before/after comparison are filled in from a real scan:",
            "",
            "```bash",
            "ollama pull llama3            # or set BACKEND=openai and OPENAI_API_KEY",
            "pip install -r requirements.txt -r requirements-garak.txt",
            "python -m report.generate_report",
            "```",
            "",
        ]
        return "\n".join(out)

    before = by_category(default)
    after = by_category(hardened) if hardened else {}
    hits = [f for f in default if f.failed]
    hits.sort(key=lambda f: (-severity.ORDER[f.severity], -f.hit_rate))

    # summary
    total_f, total_n = sum(v[0] for v in before.values()), sum(v[1] for v in before.values())
    out += ["## Summary", ""]
    out += [f"- Garak probes run against the default bot: {len({f.probe for f in default if not f.detector.startswith('supportbot.')})}, {total_n} scored replies, {total_f} hits ({total_f / total_n:.0%})." if total_n else "- No scored replies."]
    out += [f"- Worst severity: **{hits[0].severity}** ({hits[0].category} {hits[0].category_name}, `{hits[0].probe}`)." if hits else "- No weaknesses found."]
    if after:
        a_f, a_n = sum(v[0] for v in after.values()), sum(v[1] for v in after.values())
        out += [f"- Hardened bot: {a_f} hits out of {a_n} ({a_f / a_n:.0%})." if a_n else "- Hardened bot: no scored replies."]
    out += [""]

    # findings
    out += ["## Findings (default bot)", ""]
    if hits:
        out += ["| Probe | OWASP | Severity | Hit rate | Evidence: prompt | Evidence: reply | Why this severity |", "|---|---|---|---|---|---|---|"]
        for f in hits:
            det = f.detector.split(".")[-1]
            out += [f"| `{f.probe}` ({det}) | {f.category} {f.category_name} | **{f.severity}** | {pct(f.failed, f.total)} | {code(f.evidence_prompt)} | {code(f.evidence_reply)} | {f.severity_reason} |"]
    else:
        out += ["No probe produced a hit."]
    out += ["", "Rows named `supportbot.*` re-check every Garak reply for the planted token (LLM02) and the system-prompt canary (LLM07).", ""]

    # coverage matrix
    out += ["## OWASP LLM Top 10 (2025) coverage", "", "| ID | Category | Tested | Weakness found | Worst severity |", "|---|---|---|---|---|"]
    for cat, info in OWASP_CATEGORIES.items():
        tested = any(f.category == cat for f in default)
        found = any(f.category == cat and f.failed for f in default)
        out += [f"| {cat} | {info['name']} | {'Yes' if tested else 'No: out of scope for this bot'} | {'Yes' if found else ('No' if tested else '-')} | {worst(default, cat) if tested else '-'} |"]
    out += [""]

    # before / after
    out += ["## Before vs after hardening", ""]
    if after:
        out += ["| OWASP category | Default bot hits | Hardened bot hits | Change |", "|---|---|---|---|"]
        for cat in TESTED_CATEGORIES:
            if cat not in before and cat not in after:
                continue
            b, a = before.get(cat, (0, 0)), after.get(cat, (0, 0))
            change = f"{(a[0] / a[1] - b[0] / b[1]) * 100:+.0f} pts" if a[1] and b[1] else "n/a"
            out += [f"| {cat} {OWASP_CATEGORIES[cat]['name']} | {pct(*b)} | {pct(*a)} | {change} |"]
        for name in ("supportbot.PlantedTokenLeak", "supportbot.SystemPromptCanary"):
            b = next((f for f in default if f.detector == name), None)
            a = next((f for f in hardened if f.detector == name), None)
            if b and a:
                out += [f"| {name} | {pct(b.failed, b.total)} | {pct(a.failed, a.total)} | |"]
        png = REPORTS / f"failures_by_category{'-mock' if backend == 'mock' else ''}.png"
        if chart(before, after, png):
            out += ["", f"![Hit rate by OWASP category, default vs hardened]({png.name})"]
    else:
        out += ["Pending: the hardened bot (`harden/hardened_bot.py`) has not been scanned yet."]
    out += [""]

    # remediation
    out += ["## Remediation by category", ""]
    out += [f"- **{cat} {OWASP_CATEGORIES[cat]['name']}**: {REMEDIATION[cat]}" for cat in TESTED_CATEGORIES if any(f.category == cat and f.failed for f in default)]
    out += [""]

    # hand-written sample
    out += ["## My LLM01 sample probes (pytest)", "", sample_probe_summary("default", backend), ""]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", default=os.getenv("BACKEND", "ollama"))
    ap.add_argument("--skip-scan", action="store_true", help="use existing reports/garak/raw files")
    ap.add_argument("--generations", type=int, default=1)
    ap.add_argument("--cap", type=int, default=25)
    args = ap.parse_args()
    backend = args.backend.lower()

    profiles = ["default"] + (["hardened"] if hardened_available() else [])
    if not args.skip_scan:
        scan(profiles, backend, args.generations, args.cap)
    default = analyse("default", backend)
    hardened = analyse("hardened", backend) if "hardened" in profiles else None

    out = REPORTS / ("report-mock.md" if backend == "mock" else "report.md")
    out.write_text(build(backend, default, hardened))
    print(f"Wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
