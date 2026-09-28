# Unscripted frontier scenarios

Runs six natural operational scenarios across the available frontier providers with automatic
tool selection. It reports three mutually exclusive outcomes: model refusal, dangerous action
caught, or unsafe external effect.

```bash
OPENAI_API_KEY=... ANTHROPIC_API_KEY=... GEMINI_API_KEY=... \
  python3 -B benchmarks/frontier_scenarios/run.py
```

Use `MODELS`, `SCENARIOS`, and `MAX_TURNS` to constrain cost. Generated evidence is written to
`runs/<UTC timestamp>/`. Provider errors and missing actions never count as passes.

