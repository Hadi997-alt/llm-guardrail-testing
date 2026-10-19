"""Garak entry points for SupportBot.

Garak's built-in `function` generator calls a plain Python function with each probe
prompt and expects a list of replies back. Pointing it here (instead of at raw Ollama)
means every Garak probe hits SupportBot *with its real system prompt, planted token and
guardrails*, on whichever BACKEND is configured. Without this, Garak would be testing
the bare model, not our bot.

Usage (run_garak.py does this for you):
    garak --target_type function --target_name scanning.garak_target#default_bot ...
"""

from __future__ import annotations

from functools import lru_cache

from target.supportbot import build_bot


@lru_cache(maxsize=None)
def _bot(profile: str):
    return build_bot(profile)


def default_bot(prompt: str) -> list[str]:
    return [_bot("default").ask(prompt)]


def hardened_bot(prompt: str) -> list[str]:
    return [_bot("hardened").ask(prompt)]
