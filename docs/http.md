# BEA over HTTP (`bea mcp --http`)

stdio (`bea mcp`) is how MCP clients such as Claude Code, Codex or Gemini run BEA. `bea mcp --http` is for
**scripts**: one long-running BEA process that a Python (or any HTTP) client drives over the MCP Streamable HTTP
transport, reconnecting as often as it likes while its BEA sessions and targets stay alive.

```text
bea mcp --http [--port N] [--json-response] [--connection-file PATH]
```

| Flag                     | Default                           | Meaning                                                                                                                       |
| ------------------------ | --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `--port N`               | `0` (ephemeral)                   | TCP port on `127.0.0.1`. There is no `--host`: BEA never listens on another interface.                                        |
| `--json-response`        | off (SSE replies)                 | Answer each POST with one JSON body instead of a short SSE stream. Simpler for hand-written clients; drops mid-call progress. |
| `--connection-file PATH` | `<BEA_HOME>\http\connection.json` | Where the URL and token are published. Give each scripted server its own file to avoid reading another server's.              |

On start BEA prints one status line on **stderr** (regardless of `BEA_LOG_LEVEL`) and nothing on stdout:

```json
{
  "bea_http": {
    "url": "http://127.0.0.1:53817/mcp",
    "connection_file": "C:\\Users\\me\\AppData\\Local\\bea\\http\\connection.json",
    "pid": 4242
  }
}
```

## Connection file and token

The connection file (`bea.http-connection/1`) is written atomically once the listener is up:

```json
{
  "schema": "bea.http-connection/1",
  "url": "http://127.0.0.1:53817/mcp",
  "token": "<43 characters>",
  "pid": 4242,
  "run_id": "…",
  "started_at": "2026-10-28T09:00:00.000Z",
  "version": "0.1.0"
}
```

- Every request needs `Authorization: Bearer <token>`. The token is `BEA_HTTP_TOKEN` when set (32–256 characters of
  `[A-Za-z0-9_-]`), else 32 random bytes in base64url. It is **never printed or logged**; read it from the file.
- The file is removed on a clean shutdown, but only if it still belongs to this server (same `run_id`). After a
  hard kill it stays behind: check that `pid` is alive and that the URL answers before trusting it.
- **Location.** On Windows the file must live inside your user profile, whose owner-only permissions it inherits.
  With `BEA_HOME` (or `--connection-file`) outside the profile, e.g. `D:\bea`, the server refuses to start rather than
  publish the token in a directory other accounts may read. On Linux the directory is created `0700` and the file
  `0600`.
- **Who can read it.** Every process running as you, analysed targets included, can read the file and drive BEA.
  Do not run `--http` while tracing untrusted programs; analyse those in a disposable VM (see `SECURITY.md`).

## What the server accepts

Every request is checked in this order, before any body byte is read:

| Check                                                         | Failure                                           |
| ------------------------------------------------------------- | ------------------------------------------------- |
| `Host` is a loopback name (`127.0.0.1`, `localhost`, `[::1]`) | `403` (DNS-rebinding protection)                  |
| `Origin`, when present, is a loopback origin                  | `403` (browsers; non-browser clients send none)   |
| Path is `/mcp` or `/shutdown`                                 | `404`                                             |
| Bearer token matches                                          | `401` with `WWW-Authenticate: Bearer realm="bea"` |
| Body ≤ 64 MiB (`Content-Length` or streamed)                  | `413`, nothing parsed                             |

`/mcp` is the MCP Streamable HTTP endpoint (2025-era, sessionful; protocol `2025-11-25`):

- **Sessions.** A POST of `initialize` without `mcp-session-id` opens an MCP session; the reply carries its id in
  the `mcp-session-id` header. Send that header (and `Accept: application/json, text/event-stream`,
  `Content-Type: application/json`) on every later request. A second `initialize` simply opens another session.
- **Unknown or expired session id → `404`.** Initialize a new session and continue; nothing on the BEA side is lost.
- **`DELETE /mcp`** with the session header closes that MCP session. Do it when you are done (in a `finally`).
- **Capacity: 4 MCP sessions.** When a fifth `initialize` arrives, the least recently used session that has no
  request in flight is closed to make room. Only when all four have a call running is the answer `503`; retry when
  one finishes. Sessions idle for **5 minutes** are closed as well.
- **BEA sessions are not MCP sessions.** The server process owns the application: `spawn_process` targets, attached
  sessions, emulator sessions, recordings and evidence survive closing, evicting or re-initializing MCP sessions.
  Reconnect and keep using your `session_id`s. They end with `close_session`, or when the server stops.
- **Cancellation.** A `notifications/cancelled` for a running call aborts it, as over stdio.
- Requests in the 2026-07-28 per-request envelope (modern-era clients) are not separately routed in v0.1.

## Stopping the server

- **`POST /shutdown`** with the bearer token answers `202 {"shutting_down": true}` and then shuts down: stop
  accepting, close every MCP session, `close_session` semantics for every BEA session (owned targets are killed,
  attached ones detached), finalize evidence, remove the connection file, exit `0` (`1` if cleanup failed).
- **Ctrl+C** in its console (SIGINT) or SIGTERM on Linux: the same sequence, exit `130`/`143`.
- Stopping a process from a script on Windows is `TerminateProcess`, which runs **no** cleanup: owned targets still
  die with BEA's job object, but evidence is not finalized and the connection file stays. Use `/shutdown`; kill the
  `pid` from the connection file only as a fallback.
- Launch BEA as `node <package>\scripts\bea.mjs mcp --http`, **not** through the `bea.cmd` npm shim: terminating
  the shim kills `cmd.exe` and leaves node, its port and its targets running.

## Python recipe (standard library only)

The module below is the tested recipe (the HTTP boundary tests extract this block from this file and run it with the
system Python). It uses only `urllib`, launches node directly, sends `DELETE` in a `finally`, and stops the server
with `POST /shutdown`, falling back to terminating the process.

<!-- recipe: bea_http.py -->

```python
"""Drive `bea mcp --http` from Python with the standard library only (urllib)."""

import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

PROTOCOL_VERSION = "2025-11-25"
ACCEPT = "application/json, text/event-stream"


def start_server(bea_mjs, node="node", extra_args=(), connection_file=None, env=None, launch=None, timeout=60.0):
    """Start `node <bea_mjs> mcp --http` and return (process, connection).

    node runs scripts/bea.mjs directly, never the bea.cmd shim (terminating the shim would leave node running).
    Each server gets its own connection file, so a stale file from another server is never read.
    `launch` replaces the `[node, bea_mjs, "mcp"]` prefix (tests use it to run BEA from its sources).
    """
    if connection_file is None:
        connection_file = Path(tempfile.mkdtemp(prefix="bea-http-")) / "connection.json"
    connection_file = Path(connection_file)
    connection_file.parent.mkdir(parents=True, exist_ok=True)
    log = open(connection_file.with_name("server.log"), "wb")
    prefix = list(launch) if launch is not None else [node, str(bea_mjs), "mcp"]
    args = prefix + ["--http", "--port", "0", "--connection-file", str(connection_file), *extra_args]
    proc = subprocess.Popen(args, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log)
    log.close()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"BEA exited with {proc.returncode}; see {connection_file.with_name('server.log')}")
        try:
            conn = json.loads(connection_file.read_text(encoding="utf-8"))
            if conn.get("schema") == "bea.http-connection/1" and conn.get("pid") == proc.pid:
                conn["_path"] = str(connection_file)
                return proc, conn
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    proc.terminate()
    raise TimeoutError("BEA did not publish its connection file in time")


def _request(conn, method, path="/mcp", body=None, headers=None, timeout=180):
    """One authenticated request; returns (status, headers, body bytes). HTTP errors are returned, not raised."""
    url = conn["url"].rsplit("/", 1)[0] + path
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode("utf-8"))
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {conn['token']}")
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return res.status, res.headers, res.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read()


def _messages(headers, body):
    """JSON-RPC messages of a reply: one JSON body, or the `data:` lines of an SSE stream."""
    text = body.decode("utf-8")
    if (headers.get("Content-Type") or "").startswith("text/event-stream"):
        lines = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
        return [json.loads(line) for line in lines if line]
    if not text:
        return []
    parsed = json.loads(text)
    return parsed if isinstance(parsed, list) else [parsed]


class McpSession:
    """One MCP session. BEA sessions (session_id) belong to the server and survive reconnects."""

    def __init__(self, conn):
        self.conn = conn
        self.session_id = None
        self._next_id = 0

    @classmethod
    def open(cls, conn):
        session = cls(conn)
        session._initialize()
        return session

    def _rpc(self, method, params=None, notification=False):
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        if not notification:
            self._next_id += 1
            message["id"] = self._next_id
        headers = {"Content-Type": "application/json", "Accept": ACCEPT}
        if self.session_id is not None:
            headers["mcp-session-id"] = self.session_id
        status, reply_headers, body = _request(self.conn, "POST", body=message, headers=headers)
        if status == 404 and self.session_id is not None:
            raise LookupError("MCP session expired (evicted or deleted); open a new McpSession")
        if status >= 400:
            raise RuntimeError(f"HTTP {status}: {body.decode('utf-8', 'replace')}")
        if self.session_id is None:
            self.session_id = reply_headers.get("mcp-session-id")
        if notification:
            return None
        for reply in _messages(reply_headers, body):
            if reply.get("id") == message["id"]:
                if "error" in reply:
                    raise RuntimeError(f"JSON-RPC error: {reply['error']}")
                return reply["result"]
        raise RuntimeError(f"no reply to request {message['id']}")

    def _initialize(self):
        self._rpc(
            "initialize",
            {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "py", "version": "1"}},
        )
        self._rpc("notifications/initialized", notification=True)

    def call_tool(self, name, arguments=None):
        """Returns the CallToolResult. A BEA error is isError=true with {"error": {...}} in content[0].text."""
        return self._rpc("tools/call", {"name": name, "arguments": arguments or {}})

    def close(self):
        """DELETE /mcp: frees this MCP session's slot at once (BEA sessions stay open)."""
        if self.session_id is not None:
            _request(self.conn, "DELETE", headers={"mcp-session-id": self.session_id}, timeout=10)
            self.session_id = None


def stop_server(proc, conn, timeout=15.0):
    """POST /shutdown (graceful: targets closed, evidence finalized, file removed); terminate only as a fallback."""
    try:
        _request(conn, "POST", path="/shutdown", timeout=10)
        return proc.wait(timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        proc.terminate()  # TerminateProcess on Windows: no cleanup, the connection file stays
        return proc.wait(timeout=10)


if __name__ == "__main__":
    BEA_MJS = os.environ.get("BEA_MJS", r"C:\path\to\bea\scripts\bea.mjs")
    proc, conn = start_server(BEA_MJS)
    try:
        for attempt in range(2):  # reconnecting is cheap; BEA state lives in the server process
            mcp = McpSession.open(conn)
            try:
                status = mcp.call_tool("bea_status")
                print(attempt, status["structuredContent"]["server"]["run_id"])
            finally:
                mcp.close()
    finally:
        print("server exit code", stop_server(proc, conn))
```

## Troubleshooting

| Symptom                                  | Cause and fix                                                                                                    |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `401`                                    | Missing/old token: re-read the connection file (a restarted server has a new token unless `BEA_HTTP_TOKEN`).     |
| `403`                                    | A proxy or browser rewrote `Host`/`Origin`; connect to `127.0.0.1` directly.                                     |
| `404` with an `mcp-session-id`           | The MCP session was deleted, evicted (5 min idle, or LRU at capacity) or the server restarted: initialize again. |
| `503`                                    | Four MCP sessions each have a call in flight. Wait for one, or use fewer concurrent sessions.                    |
| `413`                                    | The request body is over 64 MiB. Split the batch or use the CLI with `--input` files.                            |
| `406` / `415`                            | Send `Accept: application/json, text/event-stream` and `Content-Type: application/json`.                         |
| Server refuses to start: outside profile | Move `BEA_HOME`/`--connection-file` inside your user profile (Windows).                                          |
| `cannot listen on 127.0.0.1:N`           | The port is taken; use `--port 0` and read the URL from the connection file.                                     |
