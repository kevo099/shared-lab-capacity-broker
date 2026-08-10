# Contributing

Keep changes deterministic, dependency-conscious, and safe to publish.

1. Read [DESIGN.md](DESIGN.md) before changing a domain rule or API shape.
2. Use only fictional semantic aliases and invented evidence in examples,
   tests, screenshots, issues, and commits.
3. Add a fail-closed test for every new uncertainty or malformed input.
4. Keep `src/lab_broker/domain` pure: no I/O, implicit time, network, process,
   database, environment, or framework import.
5. Keep live collection GET-only and the application credential-free.
6. Do not add persistence, approvals, reservations, or execution under a
   read-only endpoint name.
7. Do not add a mutation control because a proposed action is displayed.

Run the complete release gate:

```bash
python3 -m pip install --only-binary=:all: --no-deps -r requirements/ci.txt
python3 -m pip check
PYTHONDONTWRITEBYTECODE=1 python3 -m compileall -q src tests scripts
ruff format --check src tests scripts
ruff check src tests scripts
mypy
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -v
python3 scripts/check_public_tree.py .
python3 -m build
systemd-analyze verify deploy/lab-broker-live.service deploy/lab-broker-synthetic.service
```

Runtime code intentionally uses only the Python standard library. Test/build
dependencies are exact-pinned in project metadata or CI. A new dependency
needs a documented security and resource-use reason, an exact version, and a
reproducible install path.

Before opening a pull request, inspect both archives in `dist/`, install the
wheel into a clean environment, and run `lab-broker overview` from outside the
checkout. Never use a real private topology to make a public test pass.
