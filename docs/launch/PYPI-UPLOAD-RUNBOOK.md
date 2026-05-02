# PyPI upload runbook -- attestseal-x402 v0.1.0

Build artifacts are in `sdk/x402/dist/` (NOT committed -- build locally before each upload):

```
attestseal_x402-0.1.0-py3-none-any.whl   17 KB
attestseal_x402-0.1.0.tar.gz             18 KB
```

Both pass `twine check`. To publish:

## Step 1: Get a PyPI API token

1. Log into [pypi.org](https://pypi.org).
2. Go to Account Settings -> API tokens -> Add API token.
3. Scope: "Entire account" for first publish (subsequent publishes can be
   scoped to the `attestseal-x402` project once it exists).
4. Copy the token (starts with `pypi-`).

## Step 2: Upload

Either (a) test on TestPyPI first, recommended for first publish:

```bash
cd sdk/x402
python -m twine upload --repository testpypi dist/*
# username: __token__
# password: <paste your TestPyPI token>
```

Verify install:

```bash
pip install --index-url https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ \
            attestseal-x402
```

Or (b) go straight to real PyPI:

```bash
cd sdk/x402
python -m twine upload dist/*
# username: __token__
# password: <paste your PyPI token>
```

## Step 3: Verify

```bash
pip install attestseal-x402
python -c "import attestseal_x402; print(attestseal_x402.__version__)"
# 0.1.0
```

The PyPI page will be at:
`https://pypi.org/project/attestseal-x402/0.1.0/`

## Step 4 (optional): Save credentials for next time

Create `~/.pypirc`:

```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-<your-token>

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-<your-testpypi-token>
```

`chmod 600 ~/.pypirc`

## Re-publishing on version bump

Bump the version in `sdk/x402/pyproject.toml` and `sdk/x402/attestseal_x402/__init__.py`,
then:

```bash
cd sdk/x402
rm -rf dist/
python -m build
python -m twine upload dist/*
```

Add a CHANGELOG.md entry for the new version.
