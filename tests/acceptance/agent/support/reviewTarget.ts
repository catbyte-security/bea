import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { fixtureToolchain } from "../../../../scripts/lib/fixtures.mjs";

/**
 * A target built by the test in a temp directory (DESIGN §8.1: a test that needs a special target builds one) for the
 * partition-A review fixes driven through the REAL agent (tests/acceptance/agent/reviewFixes.test.ts). One program,
 * one mode per run (argv[1]):
 *   loop    main thread: g_counter++, step(f), GetFileAttributesW (a "file" profile API), Sleep(10)
 *   steady  main thread: g_counter++, step(f), Sleep(10) and nothing else (no rare branch: a real game loop's shape)
 *   pg      as steady, plus a private page made PAGE_READONLY before READY (page-guard re-protection cases)
 *   guard   as steady, plus a page the TARGET guards (RW | PAGE_GUARD); the loop calls touch(page + 0x40)
 * A second thread executes stdin commands (Frida's device.input), one per line, each answered with one line:
 *   priv -> PRIV=<private bytes>   counter -> COUNTER=<g_counter>   query -> PROT=0x<protect of the page>
 *   ro|rw|rx -> PROTECTED ok=<0|1> old=0x.. now=0x..   write -> WROTE prot=0x..   read -> READ v=.. prot=0x..
 *   debug -> DEBUGGED (20 x OutputDebugStringA)   raise -> RAISED (20 x RaiseException(0xE0424541), handled by a VEH)
 * READY pid=<pid> tid=<main tid> page=<%p> counter=<%p> is printed once everything is set up.
 */
const SOURCE = String.raw`
#define PSAPI_VERSION 2
#include <windows.h>
#include <psapi.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define EXPORT __declspec(dllexport)
#define NOINLINE __attribute__((noinline))
#define BEA_RAISE_CODE 0xE0424541u

EXPORT volatile LONG g_counter;
EXPORT volatile LONGLONG g_sink;
EXPORT BYTE * volatile g_page;

/* a few blocks per call: what traces count */
EXPORT NOINLINE LONGLONG step(LONGLONG x)
{
    LONGLONG acc = x;
    for (int i = 0; i < 8; i++)
        acc = (acc & 1) ? acc * 3 + 1 : acc / 2;
    return acc;
}

/* a hook point that never dereferences its argument */
EXPORT NOINLINE LONGLONG touch(void *p)
{
    return (LONGLONG)(ULONG_PTR)p >> 4;
}

static void say(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
}

static DWORD prot(void)
{
    MEMORY_BASIC_INFORMATION m;
    return g_page != NULL && VirtualQuery(g_page, &m, sizeof m) ? m.Protect : 0;
}

static LONG CALLBACK veh(EXCEPTION_POINTERS *ep)
{
    return ep->ExceptionRecord->ExceptionCode == BEA_RAISE_CODE ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
}

static DWORD WINAPI commands(LPVOID unused)
{
    char line[128];
    (void)unused;
    while (fgets(line, sizeof line, stdin)) {
        if (!strncmp(line, "priv", 4)) {
            PROCESS_MEMORY_COUNTERS_EX pmc;
            memset(&pmc, 0, sizeof pmc);
            pmc.cb = sizeof pmc;
            K32GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&pmc, sizeof pmc);
            say("PRIV=%llu\n", (unsigned long long)pmc.PrivateUsage);
        } else if (!strncmp(line, "counter", 7)) {
            say("COUNTER=%ld\n", (long)g_counter);
        } else if (!strncmp(line, "query", 5)) {
            say("PROT=0x%lx\n", (unsigned long)prot());
        } else if (!strncmp(line, "ro", 2) || !strncmp(line, "rw", 2) || !strncmp(line, "rx", 2)) {
            DWORD want = line[1] == 'w' ? PAGE_READWRITE : line[1] == 'x' ? PAGE_EXECUTE_READ : PAGE_READONLY;
            DWORD old = 0;
            BOOL ok = VirtualProtect(g_page, 4096, want, &old);
            say("PROTECTED ok=%d old=0x%lx now=0x%lx\n", ok ? 1 : 0, (unsigned long)old, (unsigned long)prot());
        } else if (!strncmp(line, "write", 5)) {
            g_page[8] = (BYTE)(g_page[8] + 1);
            say("WROTE prot=0x%lx\n", (unsigned long)prot());
        } else if (!strncmp(line, "read", 4)) {
            unsigned v = g_page[8];
            say("READ v=%u prot=0x%lx\n", v, (unsigned long)prot());
        } else if (!strncmp(line, "debug", 5)) {
            for (int i = 0; i < 20; i++)
                OutputDebugStringA("bea review target\n");
            say("DEBUGGED\n");
        } else if (!strncmp(line, "raise", 5)) {
            for (int i = 0; i < 20; i++)
                RaiseException(BEA_RAISE_CODE, 0, 0, NULL);
            say("RAISED\n");
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "loop";
    int files = !strcmp(mode, "loop");
    int guarded = !strcmp(mode, "guard");
    setvbuf(stdout, NULL, _IONBF, 0);
    if (!strcmp(mode, "pg")) {
        DWORD old;
        g_page = (BYTE *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        VirtualProtect(g_page, 4096, PAGE_READONLY, &old);
    } else if (guarded) {
        g_page = (BYTE *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE | PAGE_GUARD);
    }
    AddVectoredExceptionHandler(1, veh);
    HANDLE t = CreateThread(NULL, 0, commands, NULL, 0, NULL);
    if (t != NULL)
        CloseHandle(t);
    say("READY pid=%lu tid=%lu page=%p counter=%p\n", GetCurrentProcessId(), GetCurrentThreadId(), (void *)g_page,
        (void *)&g_counter);
    for (LONGLONG f = 0;; f++) {
        g_counter++;
        g_sink += step(f);
        if (guarded)
            g_sink += touch(g_page + 0x40);
        if (files)
            GetFileAttributesW(L"C:\\Windows");
        Sleep(10);
    }
}
`;

export const REVIEW_TARGET_EXE = "bea_review_target.exe";

export interface BuiltTarget {
  readonly path: string;
  readonly cleanup: () => Promise<void>;
}

const run = (command: string, args: readonly string[], cwd: string): Promise<{ code: number | null; out: string }> =>
  new Promise((resolve, reject) => {
    const child = spawn(command, [...args], { cwd, windowsHide: true });
    let out = "";
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => (out += chunk));
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => (out += chunk));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, out }));
  });

/** gcc -O1 (the fixtures' toolchain) into a fresh temp directory; cleanup removes it once the target has exited. */
export const buildReviewTarget = async (): Promise<BuiltTarget> => {
  const toolchain = fixtureToolchain();
  if ("unavailable" in toolchain) throw new Error(toolchain.unavailable);
  const dir = await mkdtemp(join(tmpdir(), "bea-review-a-"));
  const cleanup = (): Promise<void> => rm(dir, { recursive: true, force: true, maxRetries: 5 }).catch(() => undefined);
  try {
    await writeFile(join(dir, "bea_review_target.c"), SOURCE);
    const built = await run(
      toolchain.cc.path,
      ["-O1", "-Wall", "-Wl,--no-insert-timestamp", "-o", REVIEW_TARGET_EXE, "bea_review_target.c"],
      dir,
    );
    if (built.code !== 0) throw new Error(`gcc failed (${String(built.code)}): ${built.out}`);
    return { path: join(dir, REVIEW_TARGET_EXE), cleanup };
  } catch (cause) {
    await cleanup();
    throw cause;
  }
};
