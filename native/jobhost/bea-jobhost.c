/*
 * bea-jobhost.c -- BEA Windows process-containment helper, protocol 1.
 *
 * One helper process per BEA-owned target (adopt/spawn) or per attached target (watch).
 *
 *   bea-jobhost adopt   <pid> <creationTime100ns> [--tolerance-100ns N] [--expect-image PATH]
 *                       [--expect-parent PID] [--mem-limit BYTES] [--kill-on-root-exit]
 *   bea-jobhost spawn   [--suspended] [--stdin-fd4] [--mem-limit BYTES] [--kill-on-root-exit]
 *                       -- <absolute-exe> [args...]
 *   bea-jobhost watch   <pid> <creationTime100ns> [--tolerance-100ns N]
 *   bea-jobhost inspect <pid>
 *   bea-jobhost probe
 *   bea-jobhost version
 *
 * Containment (adopt/spawn): ONE unnamed, non-inheritable Job Object with
 * KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION [| JOB_MEMORY], no breakaway (policy read back).
 * If this helper dies for any reason the kernel closes the last job handle and kills the tree.
 * watch/inspect never create a job and never request PROCESS_TERMINATE: they cannot kill.
 *
 * Control (fd0, ASCII lines): "kill" | "resume" | "status".  EOF or broken pipe:
 *   adopt/spawn -> terminate the job (owner went away);  watch -> exit 0 without touching the target.
 * Status: NDJSON lines on fd3 when the parent supplied one (CRT lpReserved2), otherwise stdout.
 *   spawn mode REQUIRES fd3 because fd1/fd2 carry the target's stdout/stderr.
 * 64-bit values that can exceed 2^53 (creation times) are JSON strings.
 *
 * Build (MinGW-w64): gcc -O2 -s -municode -D_WIN32_WINNT=0x0A00 -static -Wall -Wextra
 *                    -o bea-jobhost.exe bea-jobhost.c
 */
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <io.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define JH_VERSION "0.1.0"
#define JH_PROTOCOL 1

/* Exit codes: status events are authoritative; these are only a fallback. */
#define JH_EXIT_KILLED 0xBEAu /* BEA terminated the job; every job member exits with this code */
#define JH_EXIT_USAGE 0xBEA1u
#define JH_EXIT_OPEN 0xBEA2u
#define JH_EXIT_IDENTITY 0xBEA3u
#define JH_EXIT_JOB 0xBEA4u
#define JH_EXIT_ASSIGN 0xBEA5u
#define JH_EXIT_CREATE 0xBEA6u
#define JH_EXIT_MEMBERSHIP 0xBEA7u
#define JH_EXIT_STATUS 0xBEA8u
#define JH_EXIT_PROBE 0xBEA9u
#define JH_PROBE_CHILD_CODE 0x5EAu
#define JH_MAX_PROC_EVENTS 256
#define JH_SETTLE_MS 2000
/* Longest JSON path literal (quoted) a status line may carry; longer paths are reported as null. Keeps every line
 * under the wrapper's 8 KiB status-line cap (src/providers/process/statusLines.ts), which would otherwise treat a
 * truncated line from a very long path as a protocol violation. */
#define JH_PATH_JSON_MAX 6144

typedef enum { M_NONE, M_ADOPT, M_SPAWN, M_WATCH, M_INSPECT, M_PROBE, M_VERSION, M_PROBE_CHILD } Mode;

static CRITICAL_SECTION g_emitLock;
static HANDLE g_status = INVALID_HANDLE_VALUE;
static int g_statusFd3 = 0;
static Mode g_mode = M_NONE;
static HANDLE g_job, g_port, g_root, g_rootThread, g_killEvent, g_zeroEvent;
static DWORD g_rootPid;
static volatile LONG g_killReason; /* 0 none, 1 control, 2 eof */
static volatile LONG g_procEvents;
static int g_killOnRootExit;
static ULONGLONG g_t0;

/* ---------- output helpers (raw WriteFile, never CRT FILE*: see lab deadlock note) ---------- */

static void emitLine(const char* buf, int n) {
  DWORD w;
  EnterCriticalSection(&g_emitLock);
  WriteFile(g_status, buf, (DWORD)n, &w, NULL);
  LeaveCriticalSection(&g_emitLock);
}

static void emitf(const char* fmt, ...) {
  char buf[8192];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof buf - 1, fmt, ap);
  va_end(ap);
  if (n < 0) return;
  if (n > (int)sizeof buf - 2) n = (int)sizeof buf - 2;
  buf[n++] = '\n';
  emitLine(buf, n);
}

static void u64dec(ULONGLONG v, char out[24]) {
  char t[24];
  int i = 0;
  do { t[i++] = (char)('0' + (v % 10)); v /= 10; } while (v);
  int o = 0;
  while (i) out[o++] = t[--i];
  out[o] = 0;
}

/* JSON string literal (quoted) from a wide string, or `null` if absent/too long. */
static void jsonStrW(const wchar_t* w, char* out, size_t cap) {
  static char tmp[4 * 4096];
  if (cap > JH_PATH_JSON_MAX) cap = JH_PATH_JSON_MAX;
  if (!w) { strcpy(out, "null"); return; }
  int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, tmp, (int)sizeof tmp, NULL, NULL);
  if (n <= 0) { strcpy(out, "null"); return; }
  size_t o = 0;
  out[o++] = '"';
  for (int i = 0; tmp[i]; i++) {
    unsigned char c = (unsigned char)tmp[i];
    if (o + 8 >= cap) { strcpy(out, "null"); return; }
    if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = (char)c; }
    else if (c < 0x20) { o += (size_t)sprintf(out + o, "\\u%04x", c); }
    else out[o++] = (char)c;
  }
  out[o++] = '"';
  out[o] = 0;
}

static void emitError(const char* stage, DWORD win32, const char* detail) {
  emitf("{\"event\":\"error\",\"stage\":\"%s\",\"win32\":%lu,\"detail\":\"%s\"}", stage, win32,
        detail ? detail : "");
}

static __attribute__((noreturn)) void finish(UINT code) {
  /* No CRT exit(): a thread blocked on stdin must not deadlock shutdown (lab-verified). */
  ExitProcess(code);
}

/* ---------- small Win32 helpers ---------- */

static ULONGLONG creationTime(HANDLE h) {
  FILETIME c, e, k, u;
  if (!GetProcessTimes(h, &c, &e, &k, &u)) return 0;
  return ((ULONGLONG)c.dwHighDateTime << 32) | c.dwLowDateTime;
}

static int imagePath(HANDLE h, wchar_t* out, DWORD cap) {
  DWORD n = cap;
  return QueryFullProcessImageNameW(h, 0, out, &n) ? 1 : 0;
}

typedef LONG(NTAPI* NtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef struct {
  LONG ExitStatus;
  PVOID PebBaseAddress;
  ULONG_PTR AffinityMask;
  LONG BasePriority;
  ULONG_PTR UniqueProcessId;
  ULONG_PTR InheritedFromUniqueProcessId;
} BEA_PBI;

static LONGLONG parentPid(HANDLE h) {
  static NtQIP q;
  if (!q) q = (NtQIP)(void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
  BEA_PBI pbi;
  ULONG len = 0;
  if (!q || q(h, 0 /* ProcessBasicInformation */, &pbi, sizeof pbi, &len) != 0) return -1;
  return (LONGLONG)pbi.InheritedFromUniqueProcessId;
}

static DWORD activeCount(void) {
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION a;
  memset(&a, 0, sizeof a);
  if (!QueryInformationJobObject(g_job, JobObjectBasicAccountingInformation, &a, sizeof a, NULL)) return 0;
  return a.ActiveProcesses;
}

static ULONGLONG peakJobMemory(void) {
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION x;
  memset(&x, 0, sizeof x);
  if (!QueryInformationJobObject(g_job, JobObjectExtendedLimitInformation, &x, sizeof x, NULL)) return 0;
  return (ULONGLONG)x.PeakJobMemoryUsed;
}

/* The identity of the file a path names (volume serial + 128-bit file id; the 64-bit NTFS index as the fallback).
 * Opened for attributes only, sharing everything, so a running image opens too. */
static int fileIdOf(const wchar_t* path, ULONGLONG* volume, BYTE id[16]) {
  HANDLE f = CreateFileW(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                         FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (f == INVALID_HANDLE_VALUE) return 0;
  int ok = 0;
  FILE_ID_INFO info;
  memset(id, 0, 16);
  if (GetFileInformationByHandleEx(f, FileIdInfo, &info, sizeof info)) {
    *volume = info.VolumeSerialNumber;
    memcpy(id, &info.FileId, 16);
    ok = 1;
  } else {
    BY_HANDLE_FILE_INFORMATION bh;
    if (GetFileInformationByHandle(f, &bh)) {
      *volume = bh.dwVolumeSerialNumber;
      memcpy(id, &bh.nFileIndexLow, 4);
      memcpy(id + 4, &bh.nFileIndexHigh, 4);
      ok = 1;
    }
  }
  CloseHandle(f);
  return ok;
}

/* The image Windows reports (QueryFullProcessImageNameW: reparse points resolved) is the file `expected` names: the
 * same string (ordinal, case-insensitive), else the same file on disk. A program reached through a junction, a
 * directory symlink, a subst drive or an 8.3 name is reported under its resolved path; comparing strings alone refused
 * every such spawn as an identity mismatch (review fix LIFE-5). */
static int sameImage(const wchar_t* actual, const wchar_t* expected) {
  if (CompareStringOrdinal(actual, -1, expected, -1, TRUE) == CSTR_EQUAL) return 1;
  ULONGLONG va = 0, vb = 0;
  BYTE ia[16], ib[16];
  if (!fileIdOf(actual, &va, ia) || !fileIdOf(expected, &vb, ib)) return 0;
  return va == vb && memcmp(ia, ib, sizeof ia) == 0;
}

/* ---------- job creation (policy read back, completion port associated BEFORE assignment) ---------- */

static DWORD g_policyFlags;
static ULONGLONG g_memLimit;

static int makeJob(void) {
  g_job = CreateJobObjectW(NULL, NULL); /* unnamed; NULL SA => handle not inheritable */
  if (!g_job) { emitError("job-create", GetLastError(), NULL); return 0; }
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;
  memset(&info, 0, sizeof info);
  g_policyFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
  if (g_memLimit) {
    g_policyFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
    info.JobMemoryLimit = (SIZE_T)((g_memLimit + 4095) & ~(ULONGLONG)4095);
  }
  info.BasicLimitInformation.LimitFlags = g_policyFlags;
  if (!SetInformationJobObject(g_job, JobObjectExtendedLimitInformation, &info, sizeof info)) {
    emitError("job-policy", GetLastError(), "set");
    return 0;
  }
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION rb;
  memset(&rb, 0, sizeof rb);
  if (!QueryInformationJobObject(g_job, JobObjectExtendedLimitInformation, &rb, sizeof rb, NULL) ||
      rb.BasicLimitInformation.LimitFlags != g_policyFlags) {
    emitError("job-policy", GetLastError(), "readback-mismatch");
    return 0;
  }
  g_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
  JOBOBJECT_ASSOCIATE_COMPLETION_PORT acp;
  acp.CompletionKey = (PVOID)1;
  acp.CompletionPort = g_port;
  if (!g_port || !SetInformationJobObject(g_job, JobObjectAssociateCompletionPortInformation, &acp, sizeof acp)) {
    emitError("job-port", GetLastError(), NULL);
    return 0;
  }
  return 1;
}

static void policyJson(char* out, size_t cap) {
  char mem[24];
  u64dec(g_memLimit, mem);
  snprintf(out, cap,
           "{\"killOnClose\":true,\"dieOnUnhandledException\":true,\"breakawayAllowed\":false,"
           "\"memLimitBytes\":%s}",
           g_memLimit ? mem : "null");
}

/* ---------- threads ---------- */

static void emitStatusSnapshot(void) {
  int alive = g_root && WaitForSingleObject(g_root, 0) == WAIT_TIMEOUT;
  emitf("{\"event\":\"status\",\"rootAlive\":%s,\"active\":%lu,\"elapsedMs\":%lu}", alive ? "true" : "false",
        g_job ? activeCount() : 0UL, (unsigned long)(GetTickCount64() - g_t0));
}

static void handleCommand(const char* cmd) {
  if (!strcmp(cmd, "kill")) {
    if (g_mode == M_WATCH) { emitError("control", 0, "kill-not-permitted-in-watch"); return; }
    InterlockedCompareExchange(&g_killReason, 1, 0);
    SetEvent(g_killEvent);
  } else if (!strcmp(cmd, "resume")) {
    HANDLE t = InterlockedExchangePointer((PVOID*)&g_rootThread, NULL);
    if (!t) { emitError("resume", 0, "not-suspended"); return; }
    DWORD prev = ResumeThread(t);
    if (prev == (DWORD)-1) emitError("resume", GetLastError(), NULL);
    else emitf("{\"event\":\"resumed\",\"previousSuspendCount\":%lu}", prev);
    CloseHandle(t);
  } else if (!strcmp(cmd, "status")) {
    emitStatusSnapshot();
  } else if (cmd[0]) {
    emitError("control", 0, "unknown-command");
  }
}

static DWORD WINAPI controlThread(LPVOID unused) {
  (void)unused;
  HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
  char buf[256], line[64];
  size_t len = 0;
  int overflow = 0;
  DWORD n;
  while (ReadFile(in, buf, sizeof buf, &n, NULL) && n > 0) {
    for (DWORD i = 0; i < n; i++) {
      char c = buf[i];
      if (c == '\r') continue;
      if (c != '\n') {
        if (len < sizeof line - 1) line[len++] = c;
        else overflow = 1;
        continue;
      }
      line[len] = 0;
      if (overflow) emitError("control", 0, "line-too-long");
      else handleCommand(line);
      len = 0;
      overflow = 0;
    }
  }
  if (g_mode == M_WATCH) { /* owner went away: stop watching; never touch the target */
    emitf("{\"event\":\"watch-ended\",\"reason\":\"eof\"}");
    finish(0);
  }
  InterlockedCompareExchange(&g_killReason, 2, 0);
  SetEvent(g_killEvent);
  return 0;
}

static void procEvent(const char* name, DWORD pid, int abnormal) {
  LONG k = InterlockedIncrement(&g_procEvents);
  if (k <= JH_MAX_PROC_EVENTS) {
    if (abnormal < 0) emitf("{\"event\":\"%s\",\"pid\":%lu}", name, pid);
    else emitf("{\"event\":\"%s\",\"pid\":%lu,\"abnormal\":%s}", name, pid, abnormal ? "true" : "false");
  } else if (k == JH_MAX_PROC_EVENTS + 1) {
    emitf("{\"event\":\"proc-events-truncated\",\"limit\":%d}", JH_MAX_PROC_EVENTS);
  }
}

static DWORD WINAPI portThread(LPVOID unused) {
  (void)unused;
  DWORD msg;
  ULONG_PTR key;
  LPOVERLAPPED ov;
  while (GetQueuedCompletionStatus(g_port, &msg, &key, &ov, INFINITE)) {
    DWORD pid = (DWORD)(ULONG_PTR)ov;
    switch (msg) {
      case JOB_OBJECT_MSG_NEW_PROCESS: procEvent("proc-start", pid, -1); break;
      case JOB_OBJECT_MSG_EXIT_PROCESS: procEvent("proc-exit", pid, 0); break;
      case JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS: procEvent("proc-exit", pid, 1); break;
      case JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO: SetEvent(g_zeroEvent); break;
      case JOB_OBJECT_MSG_JOB_MEMORY_LIMIT: emitf("{\"event\":\"memory-limit\",\"pid\":%lu}", pid); break;
      default: break;
    }
  }
  return 0;
}

/* ---------- lifecycle loop shared by adopt and spawn ---------- */

static const char* killReasonName(void) {
  switch (g_killReason) {
    case 1: return "control";
    case 2: return "eof";
    default: return "root-exit-policy";
  }
}

static void terminateJob(const char* reason) {
  DWORD before = activeCount();
  BOOL ok = TerminateJobObject(g_job, JH_EXIT_KILLED);
  emitf("{\"event\":\"killed\",\"reason\":\"%s\",\"activeBefore\":%lu,\"ok\":%s,\"win32\":%lu}", reason, before,
        ok ? "true" : "false", ok ? 0UL : GetLastError());
}

static void emitRootExit(DWORD code, int byKill) {
  emitf("{\"event\":\"root-exit\",\"pid\":%lu,\"code\":%lu,\"codeHex\":\"0x%08lX\",\"activeAfterRoot\":%lu,"
        "\"byKill\":%s}",
        g_rootPid, code, code, activeCount(), byKill ? "true" : "false");
}

static __attribute__((noreturn)) void runLoop(void) {
  CreateThread(NULL, 0, portThread, NULL, 0, NULL);
  CreateThread(NULL, 0, controlThread, NULL, 0, NULL);
  DWORD code = STILL_ACTIVE;
  HANDLE w1[2] = {g_root, g_killEvent};
  DWORD which = WaitForMultipleObjects(2, w1, FALSE, INFINITE);
  if (which == WAIT_OBJECT_0) {
    GetExitCodeProcess(g_root, &code);
    emitRootExit(code, 0);
    if (activeCount() > 0) {
      if (g_killOnRootExit) {
        terminateJob("root-exit-policy");
      } else {
        /* Default policy: stragglers keep running until BEA kills the job (close_session) or they exit. */
        for (;;) {
          if (activeCount() == 0) break;
          HANDLE w2[2] = {g_zeroEvent, g_killEvent};
          DWORD r = WaitForMultipleObjects(2, w2, FALSE, 250);
          if (r == WAIT_OBJECT_0 + 1) { terminateJob(killReasonName()); break; }
        }
      }
    }
  } else {
    terminateJob(killReasonName());
    if (WaitForSingleObject(g_root, JH_SETTLE_MS) == WAIT_OBJECT_0) {
      GetExitCodeProcess(g_root, &code);
      emitRootExit(code, 1);
    }
  }
  /* Settle: ActiveProcesses is the source of truth; the port message is only a wake-up hint. */
  ULONGLONG s0 = GetTickCount64();
  while (activeCount() > 0 && GetTickCount64() - s0 < JH_SETTLE_MS) WaitForSingleObject(g_zeroEvent, 25);
  char peak[24];
  u64dec(peakJobMemory(), peak);
  DWORD left = activeCount();
  emitf("{\"event\":\"settled\",\"active\":%lu,\"timedOut\":%s,\"peakJobMemoryBytes\":%s,\"elapsedMs\":%lu}", left,
        left ? "true" : "false", peak, (unsigned long)(GetTickCount64() - g_t0));
  finish(code == STILL_ACTIVE ? JH_EXIT_KILLED : code);
}

/* ---------- argument parsing ---------- */

static int parseU64(const wchar_t* s, ULONGLONG* out) {
  if (!s || !*s) return 0;
  ULONGLONG v = 0;
  for (; *s; s++) {
    if (*s < L'0' || *s > L'9') return 0;
    ULONGLONG nv = v * 10 + (ULONGLONG)(*s - L'0');
    if (nv / 10 != v) return 0;
    v = nv;
  }
  *out = v;
  return 1;
}

static int isDriveAbsolute(const wchar_t* p) {
  return p && ((p[0] >= L'A' && p[0] <= L'Z') || (p[0] >= L'a' && p[0] <= L'z')) && p[1] == L':' &&
         (p[2] == L'\\' || p[2] == L'/');
}

/* ---------- identity check shared by adopt and watch ---------- */

static int checkIdentity(HANDLE h, ULONGLONG expected, ULONGLONG tol, const wchar_t* expectImage,
                         LONGLONG expectParent, ULONGLONG* actualOut, wchar_t* img, DWORD imgCap) {
  ULONGLONG actual = creationTime(h);
  *actualOut = actual;
  char a[24], e[24];
  u64dec(actual, a);
  u64dec(expected, e);
  ULONGLONG diff = actual > expected ? actual - expected : expected - actual;
  if (!actual || diff > tol) {
    emitf("{\"event\":\"error\",\"stage\":\"identity\",\"win32\":0,\"detail\":\"creation-time\",\"expected\":\"%s\","
          "\"actual\":\"%s\"}",
          e, a);
    return 0;
  }
  if (WaitForSingleObject(h, 0) == WAIT_OBJECT_0) { emitError("identity", 0, "already-exited"); return 0; }
  int haveImg = imagePath(h, img, imgCap);
  if (expectImage && (!haveImg || !sameImage(img, expectImage))) { emitError("identity", 0, "image-path"); return 0; }
  if (expectParent >= 0 && parentPid(h) != expectParent) { emitError("identity", 0, "parent-pid"); return 0; }
  if (!haveImg) img[0] = 0;
  return 1;
}

/* ---------- modes ---------- */

static __attribute__((noreturn)) void modeAdopt(int argc, wchar_t** argv) {
  ULONGLONG pid64 = 0, expected = 0, tol = 0;
  const wchar_t* expectImage = NULL;
  LONGLONG expectParent = -1;
  if (argc < 4 || !parseU64(argv[2], &pid64) || !parseU64(argv[3], &expected)) {
    emitError("usage", 0, "adopt <pid> <creationTime100ns>");
    finish(JH_EXIT_USAGE);
  }
  for (int i = 4; i < argc; i++) {
    ULONGLONG v;
    if (!wcscmp(argv[i], L"--tolerance-100ns") && i + 1 < argc && parseU64(argv[i + 1], &v)) { tol = v; i++; }
    else if (!wcscmp(argv[i], L"--expect-image") && i + 1 < argc) { expectImage = argv[++i]; }
    else if (!wcscmp(argv[i], L"--expect-parent") && i + 1 < argc && parseU64(argv[i + 1], &v)) { expectParent = (LONGLONG)v; i++; }
    else if (!wcscmp(argv[i], L"--mem-limit") && i + 1 < argc && parseU64(argv[i + 1], &v)) { g_memLimit = v; i++; }
    else if (!wcscmp(argv[i], L"--kill-on-root-exit")) g_killOnRootExit = 1;
    else { emitError("usage", 0, "unknown-option"); finish(JH_EXIT_USAGE); }
  }
  g_rootPid = (DWORD)pid64;
  g_root = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                       g_rootPid);
  if (!g_root) { emitError("open", GetLastError(), NULL); finish(JH_EXIT_OPEN); }
  static wchar_t img[4096];
  ULONGLONG actual = 0;
  if (!checkIdentity(g_root, expected, tol, expectImage, expectParent, &actual, img, 4096)) finish(JH_EXIT_IDENTITY);
  if (!makeJob()) finish(JH_EXIT_JOB);
  BOOL wasInJob = FALSE, inOurs = FALSE;
  IsProcessInJob(g_root, NULL, &wasInJob);
  if (!AssignProcessToJobObject(g_job, g_root)) {
    emitf("{\"event\":\"error\",\"stage\":\"assign\",\"win32\":%lu,\"detail\":\"\",\"wasInJob\":%s}", GetLastError(),
          wasInJob ? "true" : "false");
    finish(JH_EXIT_ASSIGN);
  }
  if (!IsProcessInJob(g_root, g_job, &inOurs) || !inOurs) { emitError("membership", GetLastError(), NULL); finish(JH_EXIT_MEMBERSHIP); }
  char ct[24], path[8192], pol[256];
  u64dec(actual, ct);
  jsonStrW(img[0] ? img : NULL, path, sizeof path);
  policyJson(pol, sizeof pol);
  emitf("{\"event\":\"adopted\",\"pid\":%lu,\"creationTime100ns\":\"%s\",\"wasInJob\":%s,\"imagePath\":%s,"
        "\"active\":%lu,\"policy\":%s}",
        g_rootPid, ct, wasInJob ? "true" : "false", path, activeCount(), pol);
  runLoop();
}

typedef struct {
  wchar_t* p;
  size_t n, cap;
  int overflow;
} WBuf;

static void wput(WBuf* b, wchar_t c) {
  if (b->n + 1 < b->cap) b->p[b->n++] = c;
  else b->overflow = 1;
  b->p[b->n] = 0;
}

/* MSVCRT/CommandLineToArgvW-compatible quoting (round-trip verified in the rea-process lab, case G5). */
static void appendArg(WBuf* b, const wchar_t* arg) {
  if (b->n) wput(b, L' ');
  if (*arg && !wcspbrk(arg, L" \t\n\v\"")) {
    for (const wchar_t* p = arg; *p; p++) wput(b, *p);
    return;
  }
  wput(b, L'"');
  for (const wchar_t* p = arg;; p++) {
    size_t bs = 0;
    while (*p == L'\\') { p++; bs++; }
    if (!*p) { for (size_t i = 0; i < bs * 2; i++) wput(b, L'\\'); break; }
    if (*p == L'"') { for (size_t i = 0; i < bs * 2 + 1; i++) wput(b, L'\\'); wput(b, L'"'); }
    else { for (size_t i = 0; i < bs; i++) wput(b, L'\\'); wput(b, *p); }
  }
  wput(b, L'"');
}

static HANDLE inheritable(HANDLE h, HANDLE fallbackNul) {
  if (h == NULL || h == INVALID_HANDLE_VALUE || GetFileType(h) == FILE_TYPE_UNKNOWN) return fallbackNul;
  SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
  return h;
}

static __attribute__((noreturn)) void modeSpawn(int argc, wchar_t** argv) {
  int suspended = 0, stdinFd4 = 0, i = 2;
  ULONGLONG v;
  for (; i < argc; i++) {
    if (!wcscmp(argv[i], L"--suspended")) suspended = 1;
    else if (!wcscmp(argv[i], L"--stdin-fd4")) stdinFd4 = 1;
    else if (!wcscmp(argv[i], L"--kill-on-root-exit")) g_killOnRootExit = 1;
    else if (!wcscmp(argv[i], L"--mem-limit") && i + 1 < argc && parseU64(argv[i + 1], &v)) { g_memLimit = v; i++; }
    else break;
  }
  if (i < argc && !wcscmp(argv[i], L"--")) i++;
  if (i >= argc || !isDriveAbsolute(argv[i])) { emitError("usage", 0, "spawn [opts] -- <absolute-exe> [args]"); finish(JH_EXIT_USAGE); }
  if (!g_statusFd3) { emitError("status", 0, "spawn-requires-fd3"); finish(JH_EXIT_STATUS); }
  static wchar_t cmd[32768];
  WBuf b = {cmd, 0, 32768, 0};
  cmd[0] = 0;
  for (int k = i; k < argc; k++) appendArg(&b, argv[k]);
  if (b.overflow) { emitError("usage", 0, "command-line-too-long"); finish(JH_EXIT_USAGE); }
  if (!makeJob()) finish(JH_EXIT_JOB);

  SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
  HANDLE nul = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING,
                           0, NULL);
  HANDLE hin = nul;
  if (stdinFd4) {
    intptr_t h4 = _get_osfhandle(4);
    if (h4 == -1 || h4 == -2) { emitError("usage", 0, "stdin-fd4-missing"); finish(JH_EXIT_USAGE); }
    hin = inheritable((HANDLE)h4, nul);
  }
  HANDLE hout = inheritable(GetStdHandle(STD_OUTPUT_HANDLE), nul);
  HANDLE herr = inheritable(GetStdHandle(STD_ERROR_HANDLE), nul);
  HANDLE list[3];
  int k = 0;
  list[k++] = hin;
  if (hout != hin) list[k++] = hout;
  if (herr != hin && herr != hout) list[k++] = herr;

  SIZE_T size = 0;
  InitializeProcThreadAttributeList(NULL, 2, 0, &size);
  LPPROC_THREAD_ATTRIBUTE_LIST attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
  if (!attrs || !InitializeProcThreadAttributeList(attrs, 2, 0, &size) ||
      !UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &g_job, sizeof g_job, NULL, NULL) ||
      !UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, list, (SIZE_T)k * sizeof(HANDLE), NULL,
                                 NULL)) {
    emitError("create", GetLastError(), "attributes");
    finish(JH_EXIT_CREATE);
  }
  STARTUPINFOEXW si;
  memset(&si, 0, sizeof si);
  si.StartupInfo.cb = sizeof si;
  si.StartupInfo.dwFlags = STARTF_USESTDHANDLES; /* no STARTF_USESHOWWINDOW: GUI targets show normally */
  si.StartupInfo.hStdInput = hin;
  si.StartupInfo.hStdOutput = hout;
  si.StartupInfo.hStdError = herr;
  si.lpAttributeList = attrs;
  PROCESS_INFORMATION pi;
  if (!CreateProcessW(argv[i], cmd, NULL, NULL, TRUE,
                      CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                      NULL, NULL, &si.StartupInfo, &pi)) {
    emitError("create", GetLastError(), NULL); /* 740 = ERROR_ELEVATION_REQUIRED */
    finish(JH_EXIT_CREATE);
  }
  BOOL inOurs = FALSE;
  if (!IsProcessInJob(pi.hProcess, g_job, &inOurs) || !inOurs) {
    TerminateProcess(pi.hProcess, JH_EXIT_MEMBERSHIP);
    emitError("membership", GetLastError(), NULL);
    finish(JH_EXIT_MEMBERSHIP);
  }
  g_root = pi.hProcess;
  g_rootPid = pi.dwProcessId;
  static wchar_t img[4096];
  if (!imagePath(g_root, img, 4096)) img[0] = 0;
  char ct[24], path[8192], pol[256];
  u64dec(creationTime(g_root), ct);
  jsonStrW(img[0] ? img : NULL, path, sizeof path);
  policyJson(pol, sizeof pol);
  if (suspended) g_rootThread = pi.hThread;
  else { ResumeThread(pi.hThread); CloseHandle(pi.hThread); }
  emitf("{\"event\":\"started\",\"pid\":%lu,\"tid\":%lu,\"creationTime100ns\":\"%s\",\"suspended\":%s,"
        "\"imagePath\":%s,\"policy\":%s}",
        g_rootPid, pi.dwThreadId, ct, suspended ? "true" : "false", path, pol);
  runLoop();
}

static __attribute__((noreturn)) void modeWatch(int argc, wchar_t** argv) {
  ULONGLONG pid64 = 0, expected = 0, tol = 0, v;
  if (argc < 4 || !parseU64(argv[2], &pid64) || !parseU64(argv[3], &expected)) {
    emitError("usage", 0, "watch <pid> <creationTime100ns>");
    finish(JH_EXIT_USAGE);
  }
  for (int i = 4; i < argc; i++) {
    if (!wcscmp(argv[i], L"--tolerance-100ns") && i + 1 < argc && parseU64(argv[i + 1], &v)) { tol = v; i++; }
    else { emitError("usage", 0, "unknown-option"); finish(JH_EXIT_USAGE); }
  }
  g_rootPid = (DWORD)pid64;
  /* No PROCESS_TERMINATE / SET_QUOTA: this mode cannot kill or contain by construction. */
  g_root = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_rootPid);
  if (!g_root) { emitError("open", GetLastError(), NULL); finish(JH_EXIT_OPEN); }
  static wchar_t img[4096];
  ULONGLONG actual = 0;
  if (!checkIdentity(g_root, expected, tol, NULL, -1, &actual, img, 4096)) finish(JH_EXIT_IDENTITY);
  char ct[24], path[8192];
  u64dec(actual, ct);
  jsonStrW(img[0] ? img : NULL, path, sizeof path);
  emitf("{\"event\":\"watching\",\"pid\":%lu,\"creationTime100ns\":\"%s\",\"imagePath\":%s}", g_rootPid, ct, path);
  CreateThread(NULL, 0, controlThread, NULL, 0, NULL);
  WaitForSingleObject(g_root, INFINITE);
  DWORD code = 0;
  GetExitCodeProcess(g_root, &code);
  emitf("{\"event\":\"root-exit\",\"pid\":%lu,\"code\":%lu,\"codeHex\":\"0x%08lX\",\"activeAfterRoot\":null,"
        "\"byKill\":false}",
        g_rootPid, code, code);
  finish(0);
}

typedef BOOL(WINAPI* PIsWow64Process2)(HANDLE, USHORT*, USHORT*);
typedef BOOL(WINAPI* PIsProcessCritical)(HANDLE, PBOOL);
typedef BOOL(WINAPI* PGetProcessInformation)(HANDLE, PROCESS_INFORMATION_CLASS, LPVOID, DWORD);

static const char* tri(int known, int value) { return !known ? "null" : value ? "true" : "false"; }

static void numOrNull(int have, ULONGLONG v, char out[24]) {
  if (have) u64dec(v, out);
  else strcpy(out, "null");
}

static __attribute__((noreturn)) void modeInspect(int argc, wchar_t** argv) {
  ULONGLONG pid64 = 0;
  if (argc < 3 || !parseU64(argv[2], &pid64)) { emitError("usage", 0, "inspect <pid>"); finish(JH_EXIT_USAGE); }
  DWORD pid = (DWORD)pid64;
  const char* access = "limited+synchronize";
  HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!h && GetLastError() == ERROR_ACCESS_DENIED) {
    access = "limited";
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  }
  if (!h) { emitError("open", GetLastError(), NULL); finish(JH_EXIT_OPEN); }
  HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
  PIsWow64Process2 pWow = (PIsWow64Process2)(void*)GetProcAddress(k32, "IsWow64Process2");
  PIsProcessCritical pCrit = (PIsProcessCritical)(void*)GetProcAddress(k32, "IsProcessCritical");
  PGetProcessInformation pInfo = (PGetProcessInformation)(void*)GetProcAddress(k32, "GetProcessInformation");

  ULONGLONG ct = creationTime(h);
  char cts[24];
  u64dec(ct, cts);
  static wchar_t img[4096];
  int haveImg = imagePath(h, img, 4096);
  char path[8192];
  jsonStrW(haveImg ? img : NULL, path, sizeof path);
  int exitedKnown = strcmp(access, "limited") != 0;
  int exited = exitedKnown && WaitForSingleObject(h, 0) == WAIT_OBJECT_0;
  DWORD exitCode = 0;
  int haveExit = exited && GetExitCodeProcess(h, &exitCode);
  LONGLONG ppid = parentPid(h);
  DWORD sess = 0;
  int haveSess = ProcessIdToSessionId(pid, &sess);
  BOOL crit = FALSE;
  int haveCrit = pCrit && pCrit(h, &crit);
  PROCESS_PROTECTION_LEVEL_INFORMATION pli;
  int haveProt = pInfo && pInfo(h, ProcessProtectionLevelInfo, &pli, sizeof pli);
  USHORT pm = 0, nm = 0;
  int haveWow = pWow && pWow(h, &pm, &nm);
  BOOL inJob = FALSE;
  int haveJob = IsProcessInJob(h, NULL, &inJob);
  int haveElev = 0, haveIl = 0, haveUser = 0, elevated = 0, sameUser = 0;
  DWORD ilRid = 0;
  HANDLE tok = NULL, self = NULL;
  if (OpenProcessToken(h, TOKEN_QUERY, &tok)) {
    TOKEN_ELEVATION te;
    DWORD len;
    if (GetTokenInformation(tok, TokenElevation, &te, sizeof te, &len)) { haveElev = 1; elevated = te.TokenIsElevated != 0; }
    BYTE ilb[256];
    if (GetTokenInformation(tok, TokenIntegrityLevel, ilb, sizeof ilb, &len)) {
      PSID sid = ((TOKEN_MANDATORY_LABEL*)ilb)->Label.Sid;
      ilRid = *GetSidSubAuthority(sid, (DWORD)(*GetSidSubAuthorityCount(sid) - 1));
      haveIl = 1;
    }
    BYTE ub[512], sb[512];
    if (GetTokenInformation(tok, TokenUser, ub, sizeof ub, &len) && OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &self) &&
        GetTokenInformation(self, TokenUser, sb, sizeof sb, &len)) {
      haveUser = 1;
      sameUser = EqualSid(((TOKEN_USER*)ub)->User.Sid, ((TOKEN_USER*)sb)->User.Sid) != 0;
    }
  }
  char ppidS[24], protS[24], exitS[24], sessS[24], ilS[24], ctS[32], pmS[24], nmS[24];
  numOrNull(ppid >= 0, (ULONGLONG)ppid, ppidS);
  numOrNull(haveProt, haveProt ? pli.ProtectionLevel : 0, protS);
  numOrNull(haveExit, exitCode, exitS);
  numOrNull(haveSess, sess, sessS);
  numOrNull(haveIl, ilRid, ilS);
  numOrNull(haveWow, pm, pmS);
  numOrNull(haveWow, nm, nmS);
  if (ct) snprintf(ctS, sizeof ctS, "\"%s\"", cts); else strcpy(ctS, "null");
  int isProtected = haveProt && pli.ProtectionLevel != PROTECTION_LEVEL_NONE;
  emitf("{\"event\":\"inspect\",\"pid\":%lu,\"access\":\"%s\",\"exited\":%s,\"exitCode\":%s,"
        "\"creationTime100ns\":%s,\"imagePath\":%s,\"parentPid\":%s,\"sessionId\":%s,\"critical\":%s,"
        "\"protectionLevel\":%s,\"protected\":%s,\"wow64\":%s,\"processMachine\":%s,\"nativeMachine\":%s,"
        "\"inJob\":%s,\"elevated\":%s,\"integrityRid\":%s,\"sameUser\":%s}",
        pid, access, tri(exitedKnown, exited), exitS, ctS, path, ppidS, sessS, tri(haveCrit, crit), protS,
        tri(haveProt, isProtected), tri(haveWow, pm != IMAGE_FILE_MACHINE_UNKNOWN), pmS, nmS, tri(haveJob, inJob),
        tri(haveElev, elevated), ilS, tri(haveUser, sameUser));
  finish(0);
}

/* Probe: prove containment by doing it, not by OS-version inference. */
static int probeChild(HANDLE job, int useJobList, PROCESS_INFORMATION* pi) {
  wchar_t self[MAX_PATH];
  GetModuleFileNameW(NULL, self, MAX_PATH);
  static wchar_t cmd[1024];
  WBuf b = {cmd, 0, 1024, 0};
  cmd[0] = 0;
  appendArg(&b, self);
  appendArg(&b, L"probe-child");
  SIZE_T size = 0;
  InitializeProcThreadAttributeList(NULL, 1, 0, &size);
  LPPROC_THREAD_ATTRIBUTE_LIST attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
  InitializeProcThreadAttributeList(attrs, 1, 0, &size);
  if (useJobList) UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &job, sizeof job, NULL, NULL);
  STARTUPINFOEXW si;
  memset(&si, 0, sizeof si);
  si.StartupInfo.cb = sizeof si;
  si.lpAttributeList = attrs;
  return CreateProcessW(self, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                        NULL, NULL, &si.StartupInfo, pi);
}

static __attribute__((noreturn)) void modeProbe(void) {
  int jobOk = makeJob();
  int jobListOk = 0, jobListExit = 0, adoptOk = 0, terminateOk = 0;
  PROCESS_INFORMATION a, c;
  if (jobOk && probeChild(g_job, 1, &a)) {
    BOOL in = FALSE;
    jobListOk = IsProcessInJob(a.hProcess, g_job, &in) && in;
    ResumeThread(a.hThread);
    DWORD code = 0;
    if (WaitForSingleObject(a.hProcess, 5000) == WAIT_OBJECT_0 && GetExitCodeProcess(a.hProcess, &code))
      jobListExit = code == JH_PROBE_CHILD_CODE;
    else TerminateProcess(a.hProcess, JH_EXIT_PROBE);
  }
  if (jobOk && probeChild(NULL, 0, &c)) { /* the adopt path: assign a suspended process created outside the job */
    BOOL in = FALSE;
    adoptOk = AssignProcessToJobObject(g_job, c.hProcess) && IsProcessInJob(c.hProcess, g_job, &in) && in;
    if (adoptOk && TerminateJobObject(g_job, JH_EXIT_KILLED)) {
      DWORD code = 0;
      terminateOk = WaitForSingleObject(c.hProcess, 5000) == WAIT_OBJECT_0 && GetExitCodeProcess(c.hProcess, &code) &&
                    code == JH_EXIT_KILLED;
    }
    if (!terminateOk) TerminateProcess(c.hProcess, JH_EXIT_PROBE);
  }
  BOOL helperInJob = FALSE;
  IsProcessInJob(GetCurrentProcess(), NULL, &helperInJob);
  int ok = jobOk && jobListOk && jobListExit && adoptOk && terminateOk;
  emitf("{\"event\":\"probe\",\"ok\":%s,\"jobPolicyVerified\":%s,\"jobListAttribute\":%s,\"assignedBeforeFirstInstruction\":%s,"
        "\"adoptAssign\":%s,\"terminateJob\":%s,\"helperInJob\":%s,\"statusFd3\":%s}",
        ok ? "true" : "false", jobOk ? "true" : "false", jobListOk ? "true" : "false", jobListExit ? "true" : "false",
        adoptOk ? "true" : "false", terminateOk ? "true" : "false", helperInJob ? "true" : "false",
        g_statusFd3 ? "true" : "false");
  finish(ok ? 0 : JH_EXIT_PROBE);
}

int wmain(int argc, wchar_t** argv) {
  InitializeCriticalSection(&g_emitLock);
  g_t0 = GetTickCount64();
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
  SetConsoleCtrlHandler(NULL, TRUE); /* lifetime is governed by stdin/kill/parent death, not console Ctrl-C */
  if (argc >= 2 && !wcscmp(argv[1], L"probe-child")) finish(JH_PROBE_CHILD_CODE);

  intptr_t fd3 = _get_osfhandle(3);
  if (fd3 != -1 && fd3 != -2 && GetFileType((HANDLE)fd3) == FILE_TYPE_PIPE) {
    g_status = (HANDLE)fd3;
    g_statusFd3 = 1;
  } else {
    g_status = GetStdHandle(STD_OUTPUT_HANDLE);
  }
  g_killEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
  g_zeroEvent = CreateEventW(NULL, FALSE, FALSE, NULL);

  const wchar_t* m = argc >= 2 ? argv[1] : L"";
  g_mode = !wcscmp(m, L"adopt") ? M_ADOPT : !wcscmp(m, L"spawn") ? M_SPAWN : !wcscmp(m, L"watch") ? M_WATCH
         : !wcscmp(m, L"inspect") ? M_INSPECT : !wcscmp(m, L"probe") ? M_PROBE : !wcscmp(m, L"version") ? M_VERSION
         : M_NONE;
  static const char* names[] = {"none", "adopt", "spawn", "watch", "inspect", "probe", "version", "probe-child"};
  BOOL helperInJob = FALSE;
  IsProcessInJob(GetCurrentProcess(), NULL, &helperInJob);
  emitf("{\"event\":\"hello\",\"protocol\":%d,\"version\":\"%s\",\"mode\":\"%s\",\"helperPid\":%lu,"
        "\"helperInJob\":%s,\"statusFd3\":%s}",
        JH_PROTOCOL, JH_VERSION, names[g_mode], GetCurrentProcessId(), helperInJob ? "true" : "false",
        g_statusFd3 ? "true" : "false");
  switch (g_mode) {
    case M_ADOPT: modeAdopt(argc, argv);
    case M_SPAWN: modeSpawn(argc, argv);
    case M_WATCH: modeWatch(argc, argv);
    case M_INSPECT: modeInspect(argc, argv);
    case M_PROBE: modeProbe();
    case M_VERSION: finish(0);
    default: emitError("usage", 0, "mode: adopt|spawn|watch|inspect|probe|version"); finish(JH_EXIT_USAGE);
  }
}
