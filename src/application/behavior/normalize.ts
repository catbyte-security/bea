/**
 * Path and key normalizers for api/1 rows (S6 §6.2 "Path normalization", §6.3 "Key normalization"). Host-side by
 * DESIGN §3 (`behavior/ApiSummary.ts` "profile summary builder + normalizers"); the agent ships NT names unchanged.
 *
 * Conservative choices where S6 leaves BELIEVED steps:
 *  - `\Device\HarddiskVolumeN\…` stays as is (no QueryDosDeviceW table in v0.1; Win32 callers reach NtCreateFile
 *    with `\??\C:\…` names, F9, so this only affects relative or device-form opens);
 *  - the current user's SID comes from the recording's decoders (`user_sid`) when known; otherwise any user-account
 *    SID (`S-1-5-21-…`, Azure AD `S-1-12-1-…`) under `\REGISTRY\USER\` is taken as HKCU, because a target opening
 *    another account's hive is rare and still visible as HKCU-shaped text plus the raw key in `detail.nt`.
 */

export type PathKind = "file" | "dir" | "pipe" | "device" | "console" | "afd" | "unknown";

export interface NormalizedPath {
  readonly path: string;
  readonly kind: PathKind;
}

const startsWithI = (text: string, prefix: string): boolean =>
  text.length >= prefix.length && text.slice(0, prefix.length).toLowerCase() === prefix.toLowerCase();

/** NT object name of a file-system object → Win32-style path + kind. `dir` is decided by the caller. */
export const normalizeNtPath = (nt: string): NormalizedPath => {
  if (nt.startsWith("<handle ")) return { path: nt, kind: "unknown" };
  let p = nt;
  for (const prefix of ["\\??\\", "\\DosDevices\\", "\\GLOBAL??\\"])
    if (startsWithI(p, prefix)) {
      p = p.slice(prefix.length);
      break;
    }
  if (startsWithI(p, "UNC\\")) p = `\\\\${p.slice(4)}`;
  // directory opens carry a trailing separator ("C:\dir\"); keep drive roots ("C:\") as they are
  if (p.length > 3 && p.endsWith("\\")) p = p.slice(0, -1);
  if (startsWithI(p, "pipe\\") || startsWithI(nt, "\\Device\\NamedPipe")) return { path: p, kind: "pipe" };
  if (startsWithI(nt, "\\Device\\Afd")) return { path: nt, kind: "afd" };
  if (startsWithI(nt, "\\Device\\ConDrv") || /^(?:CONOUT\$|CONIN\$|CON)$/iu.test(p))
    return { path: p, kind: "console" };
  if (startsWithI(p, "\\Device\\") && !startsWithI(p, "\\Device\\HarddiskVolume")) return { path: p, kind: "device" };
  return { path: p, kind: "file" };
};

const USER_SID_RE = /^S-1-(?:5-21|12-1)-[0-9-]+$/iu;

/** NT registry key name → HKLM/HKCU/HKU form (S6 §6.3). */
export const normalizeKey = (nt: string, userSid: string | null): string => {
  if (nt.startsWith("<handle ")) return nt;
  if (startsWithI(nt, "\\REGISTRY\\MACHINE")) return `HKLM${nt.slice("\\REGISTRY\\MACHINE".length)}`;
  if (startsWithI(nt, "\\REGISTRY\\USER\\")) {
    const rest = nt.slice("\\REGISTRY\\USER\\".length);
    const cut = rest.indexOf("\\");
    const first = cut < 0 ? rest : rest.slice(0, cut);
    const tail = cut < 0 ? "" : rest.slice(cut);
    const sid = first.endsWith("_Classes") ? first.slice(0, -"_Classes".length) : first;
    const isCurrent = userSid !== null ? sid.toLowerCase() === userSid.toLowerCase() : USER_SID_RE.test(sid);
    if (isCurrent) return first.endsWith("_Classes") ? `HKCU\\Software\\Classes${tail}` : `HKCU${tail}`;
    return `HKU\\${rest}`;
  }
  if (startsWithI(nt, "\\REGISTRY\\")) return `HKEY_REGISTRY${nt.slice("\\REGISTRY".length)}`;
  return nt;
};

/** S6 §6.1: URL query strings and fragments are stripped by default. */
export const stripQuery = (url: string): { readonly text: string; readonly stripped: boolean } => {
  const cut = url.search(/[?#]/u);
  return cut < 0 ? { text: url, stripped: false } : { text: url.slice(0, cut), stripped: true };
};
