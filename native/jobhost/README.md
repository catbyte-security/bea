# bea-jobhost (protocol 1)

`bea-jobhost.exe` is BEA's Windows process-containment helper (DESIGN §5.2, annex S3 §5). One helper runs per
BEA-owned target (`adopt`, `spawn`) or per attached target (`watch`). The TypeScript wrapper is
`src/providers/process/**` (WP2-PROC); the status-line schema is `src/domain/jobhostProtocol.ts`.

| Mode                                                                                                                    | Used by                                                 | Can kill?                                           |
| ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | --------------------------------------------------- |
| `adopt <pid> <ct> [--tolerance-100ns N] [--expect-image P] [--expect-parent PID] [--mem-limit B] [--kill-on-root-exit]` | `spawn_process` (Frida spawn, then adopt before resume) | yes: the job, via `kill`, stdin EOF or helper death |
| `spawn [--suspended] [--stdin-fd4] [--mem-limit B] [--kill-on-root-exit] -- <exe> [args]`                               | BEA helpers (the emulator bridge)                       | yes: the job                                        |
| `watch <pid> <ct> [--tolerance-100ns N]`                                                                                | attached targets                                        | **no**: no job, no TERMINATE right, `kill` refused  |
| `inspect <pid>`                                                                                                         | attach policy, `host:elevation` doctor check            | no                                                  |
| `probe`                                                                                                                 | `bea doctor`, `bea_status`                              | its own two children only                           |
| `version`                                                                                                               | `jobhost:binary` doctor check                           | no                                                  |

- **Job**: unnamed, not inheritable, `KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION` (+ `JOB_MEMORY` with
  `--mem-limit`), policy read back for exact equality (no breakaway), completion port associated before any process
  joins. If the helper dies for any reason the kernel closes the last job handle and kills the tree.
- **Status**: one JSON object per line on fd3 (stdout when fd3 is absent; `spawn` requires fd3), first line `hello`.
  64-bit values are decimal strings. The wrapper validates every line; a failing line terminates the helper.
- **Control**: fd0 lines `kill | resume | status`; EOF means `kill` (adopt/spawn) or `watch-ended` (watch). Raw
  `ReadFile` and `ExitProcess` only (CRT `fgets` in a thread plus `exit()` deadlocks).
- **Stragglers** survive the root's exit until `kill` (or stdin EOF); `--kill-on-root-exit` only for BEA's own helpers.
- **Exit codes** (fallback only): the root's code, `0xBEA` (job killed), `0xBEA1`–`0xBEA9` stage failures, `0x5EA`
  (probe child).

## Build

`npm run build:native` (`scripts/build-native.mjs`, also part of `npm run build`):

```
gcc -O2 -s -municode -D_WIN32_WINNT=0x0A00 -static -Wall -Wextra -Werror -Wl,--no-insert-timestamp \
    -o dist/native/win32-x64/bea-jobhost.exe native/jobhost/bea-jobhost.c
```

It writes `dist/native/win32-x64/bea-jobhost.json` (`bea.native-build/1`) with the exe's sha256; the wrapper refuses
a binary whose digest differs (`capability_unavailable{capability:"jobhost", reason:"binary-digest-mismatch"}`).
The binary is a build output and is never committed.

## Changes since S3 Appendix A

- `JH_PATH_JSON_MAX` (6,144 B): image paths whose JSON literal is longer are reported as `null`, so every status line
  stays below the wrapper's 8 KiB line cap. Before, a path near the 4,096-character buffer limit could make `emitf`
  truncate a line into invalid JSON, which the wrapper must treat as a protocol violation. Protocol unchanged.
- `--expect-image` (review fix LIFE-5): `QueryFullProcessImageNameW` reports the reparse-resolved path, so a program
  reached through a junction, a directory symlink, a subst drive or an 8.3 name never matched as a string, and every
  such adopt failed with `identity`/`image-path`. When the strings differ, the helper now compares file identity (volume
  serial number + 128-bit `FileIdInfo` id, the 64-bit NTFS index as fallback; both paths opened for attributes only):
  the same file passes, a different file is still refused with `image-path`. Protocol unchanged.

## Tests

- `tests/unit/process/**` (fast lane, fake helper): protocol parsing, error mapping, kill/escalation state machine.
- `tests/boundary/process/**` (`npm run test:process`, serial, Windows): the S3 `jh-smoke.mjs` / `jh-fd4.mjs` cases
  against the built helper, run from a dist snapshot (`node scripts/snapshot-dist.mjs <name>`, `BEA_DIST_DIR`).
