# Contributing to Aesop

Thanks for your interest in contributing to Aesop.

## Getting started

```bash
git clone https://github.com/muhammedcan/aesop.git
cd aesop
uv sync
uv run pytest
```

## Adding a new rule

1. Create a new file in `aesop/rules/` (e.g. `my_rule.py`)
2. Extend `BaseRule`, set `rule_id`, `name`, `description`
3. Implement `evaluate()` to return a list of `Finding` objects
4. Call `register(MyRule())` at module level
5. Add the import to `aesop/rules/registry.py` in `_ensure_rules_loaded()`
6. Add a matching category to `aesop/domain/enums.py` → `FindingCategory`
7. Add ATLAS technique mappings to `aesop/atlas/data/atlas_minimal.json`
8. Write tests in `tests/`

## Guidelines

- Keep rule files under 250 lines
- Every finding must include `evidence` grounded in the spec
- Rules must be deterministic — no randomness, no LLM calls
- Run `uv run pytest` before submitting

## Reporting issues

Open an issue at [github.com/muhammedcan/aesop/issues](https://github.com/muhammedcan/aesop/issues).
