# Guardrail robustness report: SupportBot

Target: SupportBot (local, defined in `target/supportbot.py`) · Backend: `ollama` · Model: `llama3` · Generated: 2026-10-19 09:31 UTC

## Status: pending a real run

No Garak results for this backend yet. Findings, evidence, severity ratings and the before/after comparison are filled in from a real scan:

```bash
ollama pull llama3            # or set BACKEND=openai and OPENAI_API_KEY
pip install -r requirements.txt -r requirements-garak.txt
python -m report.generate_report
```
