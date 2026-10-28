/* Test-only helper pidcheck.exe: owned-PID leak oracle.
 * Usage: pidcheck.exe <pid> [<creationTime100ns>]
 * Prints {"pid":N,"alive":bool,"creation100ns":"T"|null,"matches":bool|null,"exit_code":N|null} and exits 0.
 * alive = process object exists and has not exited; matches = creation time equals the argument (pid-reuse guard).
 * Build (reference): gcc -O2 -Wl,--no-insert-timestamp -o pidcheck.exe pidcheck.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: pidcheck <pid> [creation100ns]\n"); return 2; }
    DWORD pid = (DWORD)strtoul(argv[1], NULL, 10);
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (!h) { printf("{\"pid\":%lu,\"alive\":false,\"creation100ns\":null,\"matches\":null,\"exit_code\":null}\n", pid); return 0; }
    FILETIME c, e, k, u; DWORD code = 0;
    GetProcessTimes(h, &c, &e, &k, &u);
    unsigned long long ct = ((unsigned long long)c.dwHighDateTime << 32) | c.dwLowDateTime;
    int alive = WaitForSingleObject(h, 0) == WAIT_TIMEOUT;
    GetExitCodeProcess(h, &code);
    const char *m = argc > 2 ? (strtoull(argv[2], NULL, 10) == ct ? "true" : "false") : "null";
    if (alive) printf("{\"pid\":%lu,\"alive\":true,\"creation100ns\":\"%llu\",\"matches\":%s,\"exit_code\":null}\n", pid, ct, m);
    else printf("{\"pid\":%lu,\"alive\":false,\"creation100ns\":\"%llu\",\"matches\":%s,\"exit_code\":%lu}\n", pid, ct, m, code);
    CloseHandle(h);
    return 0;
}
