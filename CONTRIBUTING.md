# Contributing

Use Python 3.12 or newer and install the development extra:

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
make check
make test
```

Keep changes focused. Reuse existing contracts and policy paths before introducing an abstraction. For a security fix, include the smallest test that demonstrates the broken invariant and fails without the fix. For harness changes, preserve equal tasks, seeds, and fault profiles across comparison modes.

Run `make eval` for policy or inspection changes and `make harness` for runtime or trajectory changes. Report the commands actually run and any remaining failure. Never change a case expectation solely to make a test green.

Do not commit `.env`, credentials, local databases, customer data, or unredacted logs. Keep documentation aligned with API behavior. Avoid adding network dependencies to the deterministic test suite.

Pull requests should explain the triggering problem, resulting behavior, and validation evidence.
