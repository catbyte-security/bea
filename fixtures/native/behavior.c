/* BEA fixture behavior.exe: a deterministic "unknown program" whose file / registry / network / process /
 * module-load / memory-protection activity is fully known, confined and self-cleaning.
 * Build (reference): gcc -O2 -Wl,--no-insert-timestamp -o behavior.exe behavior.c -lws2_32
 *
 * Usage: behavior.exe --out-dir DIR [--steps file,registry,network,process,module,memory] [--reg-key NAME]
 *                     [--delay-ms D] [--child-hold-ms H] [--hold-ms H]
 *        behavior.exe --child [--hold-ms H]      (child mode: prints CHILD, sleeps H ms, exits 7)
 * Side effects: files only inside --out-dir; registry only under HKCU\Software\BEA-Fixture\<key> (deleted again);
 * network only on 127.0.0.1; child = this same exe with --child. Prints "STEP <name> ok|fail" and "DONE".
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static wchar_t g_dir[MAX_PATH];
static wchar_t g_key[128] = L"";
static DWORD g_child_hold = 0;

/* One marker line = one WriteFile: the parent and its --child share the stdout pipe, and the CRT writes an unbuffered
 * printf one character at a time, so "CHILD pid=" and "CHILDMODE pid=" could interleave mid-line (WP8 acceptance). */
static void out_line(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n >= (int)sizeof buf) n = (int)sizeof buf - 1;
    DWORD written = 0;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, (DWORD)n, &written, NULL);
}
static void wpath(wchar_t *out, const wchar_t *name) { _snwprintf(out, MAX_PATH, L"%ls\\%ls", g_dir, name); out[MAX_PATH - 1] = 0; }
static void step(const char *name, int ok) { out_line("STEP %s %s\n", name, ok ? "ok" : "fail"); }

static int do_file(void)
{
    wchar_t a[MAX_PATH], b[MAX_PATH], missing[MAX_PATH], sub[MAX_PATH], pat[MAX_PATH];
    DWORD n = 0; char buf[8] = {0}; int ok = 1;
    wpath(a, L"bea_behavior_a.txt"); wpath(b, L"bea_behavior_b.txt"); wpath(missing, L"does_not_exist.txt");
    wpath(sub, L"sub"); wpath(pat, L"*");
    HANDLE h = CreateFileW(a, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok &= h != INVALID_HANDLE_VALUE && WriteFile(h, "hello", 5, &n, NULL) && n == 5; CloseHandle(h);
    h = CreateFileW(a, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    ok &= h != INVALID_HANDLE_VALUE && ReadFile(h, buf, 5, &n, NULL) && n == 5; CloseHandle(h);
    ok &= MoveFileExW(a, b, MOVEFILE_REPLACE_EXISTING) != 0;
    ok &= GetFileAttributesW(missing) == INVALID_FILE_ATTRIBUTES;     /* probe: STATUS_OBJECT_NAME_NOT_FOUND */
    ok &= DeleteFileW(b) != 0;
    ok &= CreateDirectoryW(sub, NULL) != 0 || GetLastError() == ERROR_ALREADY_EXISTS;
    WIN32_FIND_DATAW fd; HANDLE f = FindFirstFileW(pat, &fd);
    if (f != INVALID_HANDLE_VALUE) FindClose(f); else ok = 0;
    RemoveDirectoryW(sub);
    return ok;
}

static int do_registry(void)
{
    wchar_t path[256]; HKEY k = NULL; DWORD v = 42, got = 0, sz = sizeof got; int ok = 1;
    _snwprintf(path, 256, L"Software\\BEA-Fixture\\%ls", g_key); path[255] = 0;
    ok &= RegCreateKeyExW(HKEY_CURRENT_USER, path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &k, NULL) == ERROR_SUCCESS;
    ok &= RegSetValueExW(k, L"Answer", 0, REG_DWORD, (const BYTE *)&v, sizeof v) == ERROR_SUCCESS;
    ok &= RegSetValueExW(k, L"Name", 0, REG_SZ, (const BYTE *)L"bea", 8) == ERROR_SUCCESS;
    ok &= RegQueryValueExW(k, L"Answer", NULL, NULL, (BYTE *)&got, &sz) == ERROR_SUCCESS && got == 42;
    ok &= RegDeleteValueW(k, L"Name") == ERROR_SUCCESS;
    RegCloseKey(k);
    ok &= RegDeleteKeyW(HKEY_CURRENT_USER, path) == ERROR_SUCCESS;
    HKEY nt = NULL; wchar_t product[128]; DWORD psz = sizeof product;           /* typical read-only system query */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &nt) == ERROR_SUCCESS) {
        RegQueryValueExW(nt, L"ProductName", NULL, NULL, (BYTE *)product, &psz);
        RegCloseKey(nt);
    } else ok = 0;
    return ok;
}

static int do_network(void)
{
    WSADATA wsa; int ok = WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
    struct addrinfo *ai = NULL;
    ok &= getaddrinfo("localhost", NULL, NULL, &ai) == 0; if (ai) freeaddrinfo(ai);
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), cs = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), as = INVALID_SOCKET;
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK); sa.sin_port = 0;
    int len = sizeof sa;
    ok &= bind(ls, (struct sockaddr *)&sa, sizeof sa) == 0 && listen(ls, 1) == 0 && getsockname(ls, (struct sockaddr *)&sa, &len) == 0;
    ok &= connect(cs, (struct sockaddr *)&sa, sizeof sa) == 0;
    as = accept(ls, NULL, NULL); ok &= as != INVALID_SOCKET;
    char out[16] = "BEA-PING-000000", in[16] = {0};
    ok &= send(cs, out, 16, 0) == 16 && recv(as, in, 16, MSG_WAITALL) == 16 && memcmp(in, out, 16) == 0;
    SOCKET us = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ok &= sendto(us, out, 16, 0, (struct sockaddr *)&sa, sizeof sa) == 16;   /* to our own TCP port number, UDP: dropped */
    closesocket(us); closesocket(as); closesocket(cs); closesocket(ls);
    WSACleanup();
    out_line("NET port=%u\n", (unsigned)ntohs(sa.sin_port));
    return ok;
}

static int do_process(void)
{
    wchar_t self[MAX_PATH], cmd[MAX_PATH + 64]; STARTUPINFOW si; PROCESS_INFORMATION pi; DWORD code = 0;
    GetModuleFileNameW(NULL, self, MAX_PATH);
    _snwprintf(cmd, MAX_PATH + 64, L"\"%ls\" --child --hold-ms %lu", self, (unsigned long)g_child_hold); cmd[MAX_PATH + 63] = 0;
    memset(&si, 0, sizeof si); si.cb = sizeof si;
    if (!CreateProcessW(self, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) return 0;
    out_line("CHILD pid=%lu\n", pi.dwProcessId);
    HANDLE q = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pi.dwProcessId);
    if (q) CloseHandle(q);
    int ok = 1;
    if (g_child_hold == 0) {
        ok &= WaitForSingleObject(pi.hProcess, 5000) == WAIT_OBJECT_0 && GetExitCodeProcess(pi.hProcess, &code) && code == 7;
    }
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return ok;
}

static int do_module(void)
{
    HMODULE h = LoadLibraryW(L"mathlib.dll");
    int ok = h != NULL;
    if (h) {
        float (*lerp)(float, float, float) = (float (*)(float, float, float))(void *)GetProcAddress(h, "mf_lerp");
        ok &= lerp != NULL && lerp(0.0f, 10.0f, 0.5f) == 5.0f;
        FreeLibrary(h);
    }
    ok &= LoadLibraryW(L"bea_missing_dll.dll") == NULL;                      /* failed load probe */
    return ok;
}

static int do_memory(void)
{
    DWORD old = 0; int ok = 1;
    unsigned char *code = (unsigned char *)VirtualAlloc(NULL, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ok &= code != NULL;
    if (code) {
        code[0] = 0xB8; code[1] = 7; code[2] = 0; code[3] = 0; code[4] = 0; code[5] = 0xC3;   /* mov eax,7; ret */
        ok &= VirtualProtect(code, 4096, PAGE_EXECUTE_READ, &old) != 0;                    /* RW -> RX */
        ok &= ((int (*)(void))(void *)code)() == 7;
        ok &= VirtualProtect(code, 4096, PAGE_READWRITE, &old) != 0;
        VirtualFree(code, 0, MEM_RELEASE);
    }
    void *rwx = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);        /* RWX alloc */
    ok &= rwx != NULL; if (rwx) VirtualFree(rwx, 0, MEM_RELEASE);
    return ok;
}

int main(int argc, char **argv)
{
    const char *steps = "file,registry,network,process,module,memory";
    DWORD delay = 0, hold = 0; int child = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--out-dir") && i + 1 < argc) MultiByteToWideChar(CP_UTF8, 0, argv[++i], -1, g_dir, MAX_PATH);
        else if (!strcmp(argv[i], "--steps") && i + 1 < argc) steps = argv[++i];
        else if (!strcmp(argv[i], "--reg-key") && i + 1 < argc) MultiByteToWideChar(CP_UTF8, 0, argv[++i], -1, g_key, 128);
        else if (!strcmp(argv[i], "--delay-ms") && i + 1 < argc) delay = (DWORD)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--child-hold-ms") && i + 1 < argc) g_child_hold = (DWORD)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--hold-ms") && i + 1 < argc) hold = (DWORD)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--child")) child = 1;
        else { fprintf(stderr, "unknown flag %s\n", argv[i]); return 2; }
    }
    if (child) { out_line("CHILDMODE pid=%lu\n", GetCurrentProcessId()); Sleep(hold); return 7; }
    if (!g_dir[0]) { fprintf(stderr, "--out-dir is required\n"); return 2; }
    if (!g_key[0]) _snwprintf(g_key, 128, L"run-%lu", GetCurrentProcessId());
    out_line("READY pid=%lu\n", GetCurrentProcessId());
    Sleep(delay);
    int all = 1;
    if (strstr(steps, "file")) { int ok = do_file(); step("file", ok); all &= ok; }
    if (strstr(steps, "registry")) { int ok = do_registry(); step("registry", ok); all &= ok; }
    if (strstr(steps, "network")) { int ok = do_network(); step("network", ok); all &= ok; }
    if (strstr(steps, "process")) { int ok = do_process(); step("process", ok); all &= ok; }
    if (strstr(steps, "module")) { int ok = do_module(); step("module", ok); all &= ok; }
    if (strstr(steps, "memory")) { int ok = do_memory(); step("memory", ok); all &= ok; }
    out_line("DONE ok=%d\n", all);
    Sleep(hold);
    return all ? 0 : 1;
}
