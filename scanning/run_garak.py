"""Run Garak against SupportBot and save the raw reports to reports/garak/raw/.

What Garak does: for each probe it loads a set of attack prompts written by the Garak
project (NVIDIA), sends each one to the target, and runs the probe's detector over every
reply to decide pass (resisted) or fail (hit). It writes one JSONL report per run: an
"attempt" row per prompt (prompt, reply, detector score) and an "eval" row per
probe/detector with pass/fail totals. None of the attack prompts live in this repo.

The target is scanning/garak_target.py, so Garak talks to SupportBot (system prompt,
planted token, guardrails) rather than to the bare model.

Examples:
    python -m scanning.run_garak                        # default bot, curated probes
    python -m scanning.run_garak --profile both         # default and hardened
    python -m scanning.run_garak --probes promptinject.HijackHateHumans --cap 10
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analysis.owasp_mapping import CURATED_PROBES, category_for  # noqa: E402

RAW_DIR = ROOT / "reports" / "garak" / "raw"


def run_probe(probe: str, profile: str, backend: str, generations: int, cap: int) -> bool:
    """One Garak invocation per probe, so a probe that cannot run (e.g. it needs a
    dataset download) is logged and skipped without losing the rest of the scan."""
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    config = (
        "reporting:\n"
        f"  report_dir: {RAW_DIR}\n"
        "run:\n"
        # soft cap on prompts per probe; some probes have hundreds and a local model
        # answers a few per second at best
        f"  soft_probe_prompt_cap: {cap}\n"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(config)
        cfg_path = fh.name
    prefix = f"{profile}-{backend}-{probe}"
    cmd = [
        sys.executable, "-m", "garak",
        "--config", cfg_path,
        "--target_type", "function",
        "--target_name", f"scanning.garak_target#{profile}_bot",
        "--spec", f"probes.{probe}",
        "--generations", str(generations),
        "--report_prefix", prefix,
    ]
    env = {**os.environ, "PYTHONPATH": str(ROOT), "PROMPT_PROFILE": profile, "BACKEND": backend}
    print(f"[{category_for(probe)}] {probe}  (profile={profile}, backend={backend})", flush=True)
    try:
        proc = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
    finally:
        os.unlink(cfg_path)
    report = RAW_DIR / f"{prefix}.report.jsonl"
    ok = proc.returncode == 0 and report.exists() and '"entry_type": "eval"' in report.read_text()
    if not ok:
        tail = (proc.stderr or proc.stdout).strip().splitlines()[-3:]
        print("    skipped: Garak did not finish this probe -> " + " | ".join(tail), flush=True)
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", choices=["default", "hardened", "both"], default="default")
    ap.add_argument("--backend", default=os.getenv("BACKEND", "ollama"))
    ap.add_argument("--probes", nargs="*", help="Garak probes (module.Class); default: the curated OWASP set")
    ap.add_argument("--generations", type=int, default=1, help="replies per prompt (more = better hit-rate estimate)")
    ap.add_argument("--cap", type=int, default=25, help="max prompts per probe")
    args = ap.parse_args()

    probes = args.probes or [m.probe for m in CURATED_PROBES]
    profiles = ["default", "hardened"] if args.profile == "both" else [args.profile]
    done, skipped = 0, []
    for profile in profiles:
        for probe in probes:
            if run_probe(probe, profile, args.backend.lower(), args.generations, args.cap):
                done += 1
            else:
                skipped.append(f"{profile}:{probe}")
    print(f"\nFinished {done} probe runs; raw reports in {RAW_DIR.relative_to(ROOT)}/")
    if skipped:
        print("Skipped: " + ", ".join(skipped))
    return 0 if done else 1


if __name__ == "__main__":
    raise SystemExit(main())
