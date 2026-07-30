# Contributing

Contributions are welcome.

## Development setup

1. Install Python 3.11+ and `uv`.
2. Fork and clone the repository.
3. Run `uv sync --frozen --all-groups`.
4. Make focused changes with tests.
5. Run the complete verification set:

```bash
uv run python -m compileall -q mealie_server.py tests
uv run python -m unittest discover -s tests -p 'test_*.py' -v
uv run pip-audit --skip-editable
```

## Pull requests

- Explain the Mealie version or OpenAPI operation involved.
- Add regression tests for changed request shapes or security gates.
- Preserve read-only defaults, fail-closed scopes, explicit confirmation, sensitive-path blocking, SSRF protection, and local-file confinement.
- Do not include API tokens, private URLs, exported recipes, database dumps, or other user data.
- Keep stdout reserved for MCP JSON-RPC; diagnostics belong on stderr.

For new write capabilities, introduce or extend a narrow mutation scope rather than using `all`.
