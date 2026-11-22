# Contributing to pii-screenshot-guard

Thank you for helping make Zero-Trust DLP tooling stronger!

## Local Setup

```bash
git clone https://github.com/gavicoding/pii-screenshot-guard.git
cd pii-screenshot-guard
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Rules for Contributors

1. **Zero real secrets in tests or fixtures:** Always construct synthetic test keys via string concatenation or obviously invalid dummy examples so secret scanners never flag test suites.
2. **Minimize false positives:** Prefer deterministic checksum validators (e.g., mod-11 for CPF/CNPJ, Luhn for payment cards) over bare digit regexes.
3. **Zero required external dependencies:** Keep core text scanning/redaction 100% Python stdlib; image/LLM analyzers stay optional and strictly opt-in.
4. **Never echo raw secrets:** Ensure any new rule outputs masked values through `mask_sensitive_value()`.
