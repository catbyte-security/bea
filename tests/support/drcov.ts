/**
 * An independent drcov reader (CI-M3; WP9-WATCH acceptance). Written from the format as Lighthouse and Cartographer
 * read it, not from BEA's writer: a text header (`DRCOV VERSION: <n>`, `DRCOV FLAVOR: <s>`), a module table
 * (`Module Table: version <v>, count <n>` or the v1 `Module Table: <n>`, then `Columns: …` and one row per module),
 * `BB Table: <m> bbs`, then either m binary records {u32 start (module-relative), u16 size, u16 mod_id} or m text lines
 * `module[ <id>]: 0x<start>, <size>`. Module rows are split on ", " into the named columns; the path is the rest.
 */
export interface DrcovModule {
  readonly id: number;
  readonly base: bigint;
  readonly end: bigint;
  readonly entry: bigint | null;
  readonly checksum: number | null;
  readonly timestamp: number | null;
  readonly path: string;
  readonly columns: Readonly<Record<string, string>>;
}
export interface DrcovBlock {
  readonly start: number;
  readonly size: number;
  readonly moduleId: number;
}
export interface DrcovFile {
  readonly version: number;
  readonly flavor: string;
  readonly moduleTableVersion: number;
  readonly columns: readonly string[];
  readonly modules: readonly DrcovModule[];
  readonly blocks: readonly DrcovBlock[];
}

export class DrcovParseError extends Error {
  override readonly name = "DrcovParseError";
}

const V1_COLUMNS = ["id", "base", "end", "entry", "path"];

/** Header lines of the text part; the binary BB table follows the last one. */
class Lines {
  pos = 0;
  constructor(readonly data: Uint8Array) {}
  next(): string {
    const nl = this.data.indexOf(0x0a, this.pos);
    if (nl < 0) throw new DrcovParseError(`unterminated header line at byte ${String(this.pos)}`);
    const text = new TextDecoder().decode(this.data.subarray(this.pos, nl)).replace(/\r$/u, "");
    this.pos = nl + 1;
    return text;
  }
  expect(re: RegExp, what: string): RegExpExecArray {
    const text = this.next();
    const m = re.exec(text);
    if (m === null) throw new DrcovParseError(`expected ${what}, got ${JSON.stringify(text.slice(0, 80))}`);
    return m;
  }
}

/** One module row: the first columns.length-1 cells split on ", ", the last column (path) is the rest. */
const parseModuleRow = (raw: string, columns: readonly string[], i: number): DrcovModule => {
  const parts: string[] = [];
  let rest = raw;
  for (let c = 0; c < columns.length - 1; c++) {
    const cut = rest.indexOf(", ");
    if (cut < 0) throw new DrcovParseError(`module row ${String(i)} has fewer than ${String(columns.length)} columns`);
    parts.push(rest.slice(0, cut).trim());
    rest = rest.slice(cut + 2);
  }
  parts.push(rest);
  const record: Record<string, string> = {};
  columns.forEach((name, k) => {
    record[name] = parts[k] ?? "";
  });
  const big = (name: string): bigint | null => (record[name] === undefined ? null : BigInt(record[name]));
  const num = (name: string): number | null => (record[name] === undefined ? null : Number(BigInt(record[name])));
  const base = big("base") ?? big("start");
  const end = big("end");
  if (base === null || end === null) throw new DrcovParseError(`module row ${String(i)} lacks base/end`);
  return {
    id: Number(record["id"]),
    base,
    end,
    entry: big("entry"),
    checksum: num("checksum"),
    timestamp: num("timestamp"),
    path: record["path"] ?? "",
    columns: record,
  };
};

/** Either exactly bbs binary records after the header or bbs text lines. */
const parseBlocks = (lines: Lines, bbs: number): DrcovBlock[] => {
  const blocks: DrcovBlock[] = [];
  const binaryLength = bbs * 8;
  if (lines.data.length - lines.pos === binaryLength) {
    const dv = new DataView(lines.data.buffer, lines.data.byteOffset + lines.pos, binaryLength);
    for (let i = 0; i < bbs; i++)
      blocks.push({
        start: dv.getUint32(i * 8, true),
        size: dv.getUint16(i * 8 + 4, true),
        moduleId: dv.getUint16(i * 8 + 6, true),
      });
    return blocks;
  }
  for (let i = 0; i < bbs; i++) {
    const m = /^module\[\s*(\d+)\]: (0x[0-9a-fA-F]+), (\d+)$/u.exec(lines.next());
    if (m === null)
      throw new DrcovParseError(`BB ${String(i)}: neither ${String(binaryLength)} binary bytes nor a text line`);
    blocks.push({ moduleId: Number(m[1]), start: Number(BigInt(m[2] ?? "0")), size: Number(m[3]) });
  }
  return blocks;
};

export const parseDrcov = (data: Uint8Array): DrcovFile => {
  const lines = new Lines(data);
  const version = Number(lines.expect(/^DRCOV VERSION: (\d+)$/u, "DRCOV VERSION")[1]);
  const flavor = lines.expect(/^DRCOV FLAVOR: (.*)$/u, "DRCOV FLAVOR")[1] ?? "";
  const table = lines.expect(/^Module Table: (?:version (\d+), count (\d+)|(\d+))$/u, "Module Table");
  const moduleTableVersion = table[1] !== undefined ? Number(table[1]) : 1;
  const count = Number(table[2] ?? table[3]);
  const columns =
    moduleTableVersion > 1
      ? (lines.expect(/^Columns: (.*)$/u, "Columns")[1] ?? "").split(",").map((c) => c.trim())
      : V1_COLUMNS;
  const modules: DrcovModule[] = [];
  for (let i = 0; i < count; i++) modules.push(parseModuleRow(lines.next(), columns, i));
  const bbs = Number(lines.expect(/^BB Table: (\d+) bbs$/u, "BB Table")[1]);
  const blocks = parseBlocks(lines, bbs);
  for (const b of blocks)
    if (!modules.some((m) => m.id === b.moduleId))
      throw new DrcovParseError(`BB references unknown module ${String(b.moduleId)}`);
  return { version, flavor, moduleTableVersion, columns, modules, blocks };
};
