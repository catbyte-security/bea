/* Test fixture mitigated.exe (BEA-FEEDBACK items 1 and 5): a process that turns on Windows process mitigations for
 * itself, the way Chrome's sandboxed GPU process and renderers run, and that names its threads with
 * SetThreadDescription, the way Chrome names CrGpuMain and VizCompositorThread.
 *
 *   mitigated.exe [--cig] [--acg] [--lifetime-ms N]
 *
 *   --cig   ProcessSignaturePolicy.MicrosoftSignedOnly = 1 (Code Integrity Guard): only Microsoft-signed images load
 *           from now on, so an unsigned frida-agent.dll cannot be injected.
 *   --acg   ProcessDynamicCodePolicy.ProhibitDynamicCode = 1 (Arbitrary Code Guard): no new executable memory and no
 *           changes to existing code pages.
 *
 * The main thread is named "bea-main" and a worker thread "bea-worker-é" (one non-ASCII character, so a reader
 * that decodes UTF-16 with the wrong width fails). Both names are set before the mitigations. The policies are read
 * back with GetProcessMitigationPolicy and printed on the ready line:
 *
 *   READY pid=<pid> cig=<0|1> acg=<0|1> signature_flags=0x<hex> dynamic_code_flags=0x<hex> worker_tid=<tid>
 *
 * The process then sleeps until it is killed or --lifetime-ms (default 600000) passes, so a forgotten fixture ends by
 * itself. A failing step prints "ERROR <step> win32=<code>" and exits with code 2.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef BOOL(WINAPI* SetPolicyFn)(PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
typedef BOOL(WINAPI* GetPolicyFn)(HANDLE, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
typedef HRESULT(WINAPI* SetDescriptionFn)(HANDLE, PCWSTR);

static HANDLE g_named;

static void fail(const char* step, DWORD code) {
  printf("ERROR %s win32=%lu\n", step, (unsigned long)code);
  fflush(stdout);
  ExitProcess(2);
}

static DWORD WINAPI worker(LPVOID arg) {
  (void)arg;
  SetEvent(g_named);
  for (;;) Sleep(1000);
  return 0;
}

int main(int argc, char** argv) {
  int cig = 0, acg = 0;
  DWORD lifetimeMs = 600000;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--cig")) cig = 1;
    else if (!strcmp(argv[i], "--acg")) acg = 1;
    else if (!strcmp(argv[i], "--lifetime-ms") && i + 1 < argc) lifetimeMs = (DWORD)strtoul(argv[++i], NULL, 10);
    else fail("usage", ERROR_INVALID_PARAMETER);
  }
  HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
  SetPolicyFn setPolicy = (SetPolicyFn)(void*)GetProcAddress(k32, "SetProcessMitigationPolicy");
  GetPolicyFn getPolicy = (GetPolicyFn)(void*)GetProcAddress(k32, "GetProcessMitigationPolicy");
  SetDescriptionFn setDescription = (SetDescriptionFn)(void*)GetProcAddress(k32, "SetThreadDescription");
  if (!setPolicy || !getPolicy || !setDescription) fail("resolve", GetLastError());

  g_named = CreateEventW(NULL, TRUE, FALSE, NULL);
  DWORD workerTid = 0;
  HANDLE thread = CreateThread(NULL, 0, worker, NULL, 0, &workerTid);
  if (!g_named || !thread) fail("thread", GetLastError());
  WaitForSingleObject(g_named, INFINITE);
  if (FAILED(setDescription(thread, L"bea-worker-é"))) fail("name-worker", GetLastError());
  if (FAILED(setDescription(GetCurrentThread(), L"bea-main"))) fail("name-main", GetLastError());

  if (cig) {
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY p;
    memset(&p, 0, sizeof p);
    p.MicrosoftSignedOnly = 1;
    if (!setPolicy(ProcessSignaturePolicy, &p, sizeof p)) fail("cig", GetLastError());
  }
  if (acg) {
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY p;
    memset(&p, 0, sizeof p);
    p.ProhibitDynamicCode = 1;
    if (!setPolicy(ProcessDynamicCodePolicy, &p, sizeof p)) fail("acg", GetLastError());
  }

  PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig;
  PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dyn;
  memset(&sig, 0, sizeof sig);
  memset(&dyn, 0, sizeof dyn);
  if (!getPolicy(GetCurrentProcess(), ProcessSignaturePolicy, &sig, sizeof sig)) fail("read-signature", GetLastError());
  if (!getPolicy(GetCurrentProcess(), ProcessDynamicCodePolicy, &dyn, sizeof dyn)) fail("read-dynamic-code", GetLastError());
  printf("READY pid=%lu cig=%d acg=%d signature_flags=0x%lx dynamic_code_flags=0x%lx worker_tid=%lu\n",
         (unsigned long)GetCurrentProcessId(), (int)sig.MicrosoftSignedOnly, (int)dyn.ProhibitDynamicCode,
         (unsigned long)sig.Flags, (unsigned long)dyn.Flags, (unsigned long)workerTid);
  fflush(stdout);
  Sleep(lifetimeMs);
  return 0;
}
