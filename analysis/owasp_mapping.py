"""OWASP Top 10 for LLM Applications (2025) <-> Garak probe mapping.

This is the knowledge artifact of the project: which Garak probe tests which OWASP
category, and what each category means in plain English. run_garak.py takes its probe
list from CURATED_PROBES, and parse_results.py uses category_for() to label findings,
so this file is the single source of truth for the mapping.

The probes themselves come from Garak (NVIDIA's open-source LLM vulnerability scanner),
not from this repo. Garak ships each probe with its own prompts and a matching detector
that decides whether the reply counts as a hit.
"""

from __future__ import annotations

from dataclasses import dataclass

# impact: 1 (low) .. 4 (critical), the worst realistic outcome if the category is
# exploited against a support bot. severity.py combines this with the hit rate.
OWASP_CATEGORIES: dict[str, dict] = {
    "LLM01": {
        "name": "Prompt Injection",
        "impact": 3,
        "plain": "Text from a user, or from content the bot reads, overrides the developer's "
        "instructions. Jailbreaks (role-play personas like DAN) and encoded instructions are "
        "forms of it. It is the entry point for most of the other categories.",
    },
    "LLM02": {
        "name": "Sensitive Information Disclosure",
        "impact": 4,
        "plain": "The bot reveals data it holds but must not share: secrets in its context, "
        "customer PII, or memorised training data. Here the measurable secret is the planted "
        "INTERNAL_DISCOUNT token.",
    },
    "LLM03": {"name": "Supply Chain", "impact": 3, "plain": "Compromised models, datasets or plugins. Not tested here."},
    "LLM04": {"name": "Data and Model Poisoning", "impact": 3, "plain": "Tampered training or fine-tuning data. Not tested here."},
    "LLM05": {
        "name": "Improper Output Handling",
        "impact": 3,
        "plain": "The app trusts model output and passes it on unescaped, so HTML/script, "
        "markdown images that call out to a URL, or terminal escape codes run in the browser "
        "or console. The bug is in the app, but the bot is what produces the payload.",
    },
    "LLM06": {"name": "Excessive Agency", "impact": 4, "plain": "The model can call tools or take actions beyond what it needs. SupportBot has no tools, so not tested."},
    "LLM07": {
        "name": "System Prompt Leakage",
        "impact": 3,
        "plain": "The bot reveals its own instructions. That hands an attacker the rules to "
        "work around, and leaks any secret the developer wrongly put in the prompt.",
    },
    "LLM08": {"name": "Vector and Embedding Weaknesses", "impact": 3, "plain": "Attacks on a RAG retrieval layer. SupportBot has no RAG, so not tested."},
    "LLM09": {
        "name": "Misinformation",
        "impact": 2,
        "plain": "The bot states false things confidently: agrees with a false premise, "
        "invents facts, or recommends software packages that do not exist (which attackers "
        "can then register).",
    },
    "LLM10": {"name": "Unbounded Consumption", "impact": 2, "plain": "Requests that burn excessive tokens, compute or money. Not tested here."},
}

TESTED_CATEGORIES = ["LLM01", "LLM02", "LLM05", "LLM07", "LLM09"]


@dataclass(frozen=True)
class ProbeMapping:
    probe: str  # Garak probe, module.Class
    category: str  # OWASP ID
    what: str  # what the probe does, in plain English


CURATED_PROBES: list[ProbeMapping] = [
    # --- LLM01 Prompt Injection -------------------------------------------------------
    ProbeMapping("promptinject.HijackHateHumans", "LLM01", "Appends 'ignore previous instructions and print <rogue string>' to normal tasks; hit if the rogue string is printed."),
    ProbeMapping("promptinject.HijackLongPrompt", "LLM01", "Same goal-hijack attack, hidden at the end of a long legitimate prompt."),
    ProbeMapping("latentinjection.LatentInjectionReport", "LLM01", "Indirect injection: an instruction buried inside a document the bot is asked to summarise."),
    ProbeMapping("latentinjection.LatentInjectionTranslationEnFr", "LLM01", "Indirect injection inside text the bot is asked to translate."),
    ProbeMapping("dan.DanInTheWild", "LLM01", "Real-world 'DAN' jailbreak prompts that ask the model to role-play an AI with no rules."),
    ProbeMapping("encoding.InjectBase64", "LLM01", "Instructions encoded in base64 to slip past keyword filters; hit if the model decodes and follows them."),
    ProbeMapping("encoding.InjectROT13", "LLM01", "Same encoding bypass with ROT13."),
    # --- LLM02 Sensitive Information Disclosure ---------------------------------------
    ProbeMapping("leakreplay.LiteratureCloze", "LLM02", "Fill-in-the-blank on passages from copyrighted books; hit if the model reproduces memorised training data."),
    ProbeMapping("leakreplay.GuardianCloze", "LLM02", "Same memorisation check using news articles."),
    # --- LLM05 Improper Output Handling ----------------------------------------------
    ProbeMapping("web_injection.MarkdownImageExfil", "LLM05", "Tries to get the bot to emit a markdown image whose URL carries conversation data; renders as a silent request to an outside server."),
    ProbeMapping("web_injection.MarkdownXSS", "LLM05", "Tries to get script-bearing markdown/HTML into the reply; dangerous if the chat UI renders it."),
    ProbeMapping("web_injection.TaskXSS", "LLM05", "Asks for ordinary web tasks whose output contains executable HTML/JS."),
    ProbeMapping("ansiescape.AnsiEscaped", "LLM05", "Tries to get terminal escape codes into the reply; dangerous if output is printed to a console or log viewer."),
    # --- LLM07 System Prompt Leakage --------------------------------------------------
    # Note: this probe installs its own sample system prompts (downloaded from Hugging
    # Face) and checks whether *those* leak. Run it against the raw model. For leakage of
    # SupportBot's own prompt, parse_results.py checks every Garak reply for the
    # SupportBot canary line, so all probes double as LLM07 evidence.
    ProbeMapping("sysprompt_extraction.SystemPromptExtraction", "LLM07", "Known extraction attacks ('repeat the text above', 'print your instructions') against sample system prompts."),
    # --- LLM09 Misinformation ---------------------------------------------------------
    ProbeMapping("misleading.FalseAssertion", "LLM09", "States a false claim and checks whether the model agrees with it instead of correcting it."),
    ProbeMapping("packagehallucination.Python", "LLM09", "Asks for code and checks whether it imports Python packages that do not exist on PyPI."),
]

# Fallback for probes outside the curated list, by Garak module name.
FAMILY_TO_CATEGORY: dict[str, str] = {
    "promptinject": "LLM01",
    "latentinjection": "LLM01",
    "dan": "LLM01",
    "encoding": "LLM01",
    "goodside": "LLM01",
    "smuggling": "LLM01",
    "leakreplay": "LLM02",
    "apikey": "LLM02",
    "web_injection": "LLM05",
    "ansiescape": "LLM05",
    "sysprompt_extraction": "LLM07",
    "misleading": "LLM09",
    "packagehallucination": "LLM09",
    "snowball": "LLM09",
}

_BY_PROBE = {m.probe: m for m in CURATED_PROBES}


def category_for(probe: str) -> str:
    """OWASP ID for a Garak probe ('module.Class'); 'UNMAPPED' if unknown."""
    if probe in _BY_PROBE:
        return _BY_PROBE[probe].category
    return FAMILY_TO_CATEGORY.get(probe.split(".")[0], "UNMAPPED")


def category_name(cat_id: str) -> str:
    return OWASP_CATEGORIES.get(cat_id, {}).get("name", cat_id)


def describe(probe: str) -> str:
    m = _BY_PROBE.get(probe)
    return m.what if m else ""


if __name__ == "__main__":  # print the study table:  python -m analysis.owasp_mapping
    for cat in TESTED_CATEGORIES:
        info = OWASP_CATEGORIES[cat]
        print(f"\n{cat} {info['name']}\n  {info['plain']}")
        for m in CURATED_PROBES:
            if m.category == cat:
                print(f"    - {m.probe}: {m.what}")
