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

2. **Bump the version** using `hatch`:

   Or set a specific version directly:

   ```bash
   hatch version 1.0.0
   ```

   > This edits `src/aio_lib_sandbox/__init__.py` in place because `pyproject.toml` uses Hatch's dynamic version path. Verify the new version with `hatch version`.

3. **Do a dry-run build** to catch any packaging issues before committing:

   ```bash
   hatch build
   ```

   Inspect the output in `dist/` to make sure the wheel and sdist look correct.

4. **Commit and tag** the version bump:

   ```bash
   git add src/aio_lib_sandbox/__init__.py
   git commit -m "$(hatch version)"
   git tag "$(hatch version)"
   ```

5. **Push the commit and tag** to `main`:

   ```bash
   git push origin main
   git push origin "$(hatch version)"
   ```

6. **CI publishes to PyPI automatically.** The `on-push-publish-to-pypi` workflow triggers because `src/aio_lib_sandbox/__init__.py` changed on `main`. Monitor progress in the [Actions tab](https://github.com/adobe/aio-lib-sandbox-python/actions).

7. **Verify the release** appeared on PyPI:

   ```
   https://pypi.org/project/aio-lib-sandbox/
   ```

   And confirm the new version is installable:

   ```bash
   pip install aio-lib-sandbox==<new-version>
   ```

8. **Create a GitHub Release** from the new tag on the [Releases page](https://github.com/adobe/aio-lib-sandbox-python/releases). Summarise what changed in the release notes.
