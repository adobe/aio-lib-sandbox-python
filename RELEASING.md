# Releasing

This document describes how to cut a new release of `aio-lib-sandbox` (Python).

## Prerequisites

Ensure your working tree is clean and you are on the `main` branch with the latest changes pulled:

```bash
git checkout main && git pull
```

Activate the virtual environment (needed to run tests and `hatch`):

```bash
source .venv/bin/activate
```

If you haven't set up the virtual environment yet:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pip install hatch
```

## Steps

1. **Run the tests** to confirm everything is green before starting:

   ```bash
   pytest
   ```

2. **Bump the version** in `pyproject.toml` using `hatch`:

   Or set a specific version directly:

   ```bash
   hatch version 0.1.0a1
   ```

   > This edits `pyproject.toml` in place. Verify the new version with `hatch version`.

3. **Do a dry-run build** to catch any packaging issues before committing:

   ```bash
   hatch build
   ```

   Inspect the output in `dist/` to make sure the wheel and sdist look correct.

4. **Commit and tag** the version bump:

   ```bash
   git add pyproject.toml
   git commit -m "chore: release v$(hatch version)"
   git tag "v$(hatch version)"
   ```

5. **Push the commit and tag** to `main`:

   ```bash
   git push origin main
   git push origin "v$(hatch version)"
   ```

6. **CI publishes to PyPI automatically.** The `on-push-publish-to-pypi` workflow triggers because `pyproject.toml` changed on `main`. Monitor progress in the [Actions tab](https://github.com/adobe/aio-lib-sandbox-python/actions).

7. **Verify the release** appeared on PyPI:

   ```
   https://pypi.org/project/aio-lib-sandbox/
   ```

   And confirm the new version is installable:

   ```bash
   pip install --pre aio-lib-sandbox==<new-version>
   ```

8. **Create a GitHub Release** from the new tag on the [Releases page](https://github.com/adobe/aio-lib-sandbox-python/releases). Summarise what changed in the release notes.

## Notes

- This package is in **alpha**. All versions use a PEP 440 pre-release suffix (e.g. `0.1.0a0`). This means `pip install aio-lib-sandbox` will not pick up the package by default — users must pass `--pre`. Keep the `a0` / `a1` suffix until the API is stable.
