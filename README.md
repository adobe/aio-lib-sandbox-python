# App Builder Sandbox SDK (Python)

[![PyPI](https://img.shields.io/pypi/v/aio-lib-sandbox.svg)](https://pypi.org/project/aio-lib-sandbox/)
[![Downloads/week](https://img.shields.io/pypi/dw/aio-lib-sandbox.svg)](https://pypi.org/project/aio-lib-sandbox/)
![Python CI](https://github.com/adobe/aio-lib-sandbox-python/workflows/Python%20CI/badge.svg)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Codecov Coverage](https://img.shields.io/codecov/c/github/adobe/aio-lib-sandbox-python/main.svg?style=flat-square)](https://codecov.io/gh/adobe/aio-lib-sandbox-python/)
![Status](https://img.shields.io/badge/status-alpha-orange.svg)

Python SDK for Adobe Runtime Sandboxes.

A **sandbox** is an ephemeral, isolated compute environment. You create one, run commands and read/write files inside it over a WebSocket session, then destroy it.

> [!WARNING]
> **Alpha.** This SDK is in active alpha development. The API surface and authentication model may change without notice. Pin exact versions; install only with `--pre`.

## Pre-requisites

To use this library, you must have Sandboxes enabled for your Runtime namespace. Please contact Michael Goberling (mgoberling@adobe.com) or Cosmin Stanciu (stanciu@adobe.com) to request this. 

## Install

```bash
pip install --pre aio-lib-sandbox
```

## Quickstart

Inside a Runtime action, credentials are read automatically from the environment.

```python
from aio_lib_sandbox import Sandbox


async def main(params):
    sandbox = await Sandbox.create(name="my-sandbox")

    result = await sandbox.exec("python --version", timeout=10_000)

    await sandbox.destroy()
    return {"stdout": result.stdout.strip()}
```

## Configuration

When running inside a Runtime action, the SDK reads credentials from the environment automatically:

| Variable | Description |
|---|---|
| `__OW_API_HOST` | Runtime API host |
| `__OW_NAMESPACE` | Runtime namespace |
| `__OW_API_KEY` | Runtime API key (basic auth) |

You can override any of these by passing them explicitly to `Sandbox.create()` or `Sandbox.get()`:

```python
sandbox = await Sandbox.create(
    api_host="https://adobeioruntime.net",
    namespace="my-namespace",
    auth="my-api-key",
    name="my-sandbox",
)
```

## Usage

### Create Sandbox

```python
from aio_lib_sandbox import Sandbox

sandbox = await Sandbox.create(
    name="my-sandbox",
    type="cpu:default",
    max_lifetime=3600,
    envs={"API_KEY": "your-api-key"},
)
```

### Get Status

```python
sandbox = await Sandbox.get(sandbox.id)
print("status:", sandbox.status)
```

### Exec

```python
result = await sandbox.exec("ls -al", timeout=10_000)
print("stdout:", result.stdout.strip())
print("exit code:", result.exit_code)
```

> Note: Commands run in the `/workspace` directory by default, this is not configurable


### File Management

```python
script = "console.log('hello from sandbox script', process.version)\n"
await sandbox.write_file("hello.js", script)

content = await sandbox.read_file("hello.js")
print("read_file content:", content.strip())

entries = await sandbox.list_files(".")
print("list_files entries:", entries)
```

### Exec a File

```python
result = await sandbox.exec("node hello.js", timeout=10_000)
print("stdout:", result.stdout.strip())
print("stderr:", result.stderr.strip())
print("exit code:", result.exit_code)
```

### Write to Stdin

#### Command start
```python
result = await sandbox.exec(
    "python process_csv.py",
    stdin="col1,col2\nval1,val2\n",
    timeout=10_000,
)
print("stdout:", result.stdout.strip())
```

#### Running command
```python
task = sandbox.exec("cat -n", timeout=10_000)

await sandbox.write_stdin(task.exec_id, "line 1\n")
await sandbox.write_stdin(task.exec_id, "line 2\n")
await sandbox.close_stdin(task.exec_id)

result = await task
print("stdout:", result.stdout.strip())
```

### Destroy

```python
await sandbox.destroy()
```

### Preview URLs

Use preview URLs to get access to servers or web services running in a sandbox on a particular port: 

```python
url = await sandbox.get_url(port=3000)
print("preview:", url)
# https://sb-abc123-va6-0-xK3mPq2nAeB-3000.sandbox-adobeioruntime.net
```

## Network Policies

Sandboxes are default-deny. All outbound traffic is blocked unless explicitly allowed.

Pass a `policy.network.egress` array at creation time to allowlist outbound endpoints, paths, or HTTP verbs.

```python
sandbox = await Sandbox.create(
    name="policy-sandbox",
    max_lifetime=300,
    policy={
        "network": {
            "egress": [
                {"host": "httpbin.org", "port": 443},
                {
                    "host": "api.github.com",
                    "port": 443,
                    "rules": [
                        {"methods": ["GET"], "pathPattern": "/repos/**"},
                    ],
                },
            ]
        }
    },
)
```
