# Contributing to NetSentry

Thanks for your interest in improving NetSentry! This is a small, focused
project, so the process is intentionally lightweight.

## Getting set up

```bash
git clone <your-fork-url>
cd netsentry
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
pytest
```

## Making changes

1. Open an issue first for anything non-trivial (new detectors, behavior
   changes, dependency additions) so we can discuss the approach.
2. Keep pull requests focused on a single change.
3. Follow the existing style: type hints on public functions, docstrings on
   modules/classes/functions, and no unrelated reformatting.
4. Add or update tests for any behavior change. Each detector has its own
   test file under `tests/` — new detectors should follow the same pattern.
5. Run the full test suite before opening a PR:

   ```bash
   pytest -q
   ```

## Adding a new detector

1. Add a class to `src/detectors.py` implementing the `Detector` interface
   defined at the top of that file.
2. Register it in `src/engine.py` (`DETECTOR_NAMES` + `build_detectors`).
3. Add a config section with sane defaults in `src/config.py` and
   `config.yaml`.
4. Add `tests/test_<name>.py` covering both the "no alert" and "alert"
   paths, using synthetic `PacketInfo` objects (see `tests/conftest.py`) —
   no live capture or root/Administrator privileges required.

## Reporting bugs / security issues

Please open an issue with steps to reproduce. See the disclaimer in the
[README](README.md) — do not use NetSentry against networks you don't have
permission to monitor.
