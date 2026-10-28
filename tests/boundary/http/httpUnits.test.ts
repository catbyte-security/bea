import { existsSync } from "node:fs";
import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { parseHttpArgs } from "../../../src/main/mcpHttp.js";
import { bearerVerifier, newHttpToken } from "../../../src/server/http/auth.js";
import {
  checkConnectionLocation,
  isWithinDirectory,
  readConnectionFile,
  removeConnectionFile,
  writeConnectionFile,
  type HttpConnection,
} from "../../../src/server/http/connectionFile.js";
import { parseJsonBody, readBodyLimited } from "../../../src/server/http/requestBody.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";

/** The pure pieces of the HTTP mode: token check, argument parsing, body limit, connection file and its location. */
const homes: TempHome[] = [];
afterEach(async () => {
  await Promise.allSettled(homes.splice(0).map((h) => h.cleanup()));
});

describe("bearer token", () => {
  it("generates 43-character base64url tokens and accepts only the exact one", () => {
    const token = newHttpToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(newHttpToken()).not.toBe(token);
    const verify = bearerVerifier(token);
    expect(verify(`Bearer ${token}`)).toBe(true);
    expect(verify(`Bearer ${token}x`)).toBe(false);
    expect(verify(`bearer ${token}`)).toBe(false);
    expect(verify(token)).toBe(false);
    expect(verify(null)).toBe(false);
    expect(verify("Bearer short")).toBe(false);
    expect(verify(`Bearer ${"a".repeat(257)}`)).toBe(false);
  });
});

describe("parseHttpArgs", () => {
  it.each([
    [["--http"], { port: 0, jsonResponse: false, connectionFile: undefined }],
    [["--http", "--port", "8123", "--json-response"], { port: 8123, jsonResponse: true, connectionFile: undefined }],
    [
      ["--http", "--connection-file", "C:\\x\\c.json"],
      { port: 0, jsonResponse: false, connectionFile: "C:\\x\\c.json" },
    ],
    [["--http", "--port=65535"], { port: 65_535, jsonResponse: false, connectionFile: undefined }],
  ])("accepts %j", (argv, expected) => {
    expect(parseHttpArgs(argv)).toEqual(expected);
  });

  it.each([["--port", "-1"], ["--port", "1e3"], ["--port", "65536"], ["--bogus"], ["positional"]])(
    "refuses %j",
    (...argv) => {
      expect(parseHttpArgs(["--http", ...argv])).toBeTypeOf("string");
    },
  );
});

describe("readBodyLimited", () => {
  const streamed = (chunks: readonly string[]): Request =>
    new Request("http://127.0.0.1/mcp", {
      method: "POST",
      body: new ReadableStream<Uint8Array>({
        start(controller) {
          for (const chunk of chunks) controller.enqueue(new TextEncoder().encode(chunk));
          controller.close();
        },
      }),
      duplex: "half",
    } as RequestInit);

  it("reads UTF-8 text up to the limit and refuses one byte more", async () => {
    expect(await readBodyLimited(streamed(["ab", "cé"]), 5)).toEqual({ tooLarge: false, text: "abcé" });
    expect(await readBodyLimited(streamed(["ab", "cé", "!"]), 5)).toEqual({ tooLarge: true });
  });

  it("refuses a declared Content-Length above the limit without reading", async () => {
    let pulled = false;
    const request = new Request("http://127.0.0.1/mcp", {
      method: "POST",
      headers: { "content-length": "100" },
      body: new ReadableStream<Uint8Array>({
        pull() {
          pulled = true;
        },
      }),
      duplex: "half",
    } as RequestInit);
    expect(await readBodyLimited(request, 99)).toEqual({ tooLarge: true });
    expect(pulled).toBe(false);
  });

  it("parses JSON without throwing", () => {
    expect(parseJsonBody('{"a":1}')).toEqual({ ok: true, value: { a: 1 } });
    expect(parseJsonBody("null")).toEqual({ ok: true, value: null });
    expect(parseJsonBody("{")).toEqual({ ok: false });
  });
});

describe("connection file", () => {
  const sample = (runId: string): HttpConnection => ({
    schema: "bea.http-connection/1",
    url: "http://127.0.0.1:1234/mcp",
    token: "t".repeat(43),
    pid: 4242,
    run_id: runId,
    started_at: "2026-01-01T00:00:00.000Z",
    version: "0.1.0",
  });

  it("publishes atomically (no temp files left), reads back, removes only its own run", async () => {
    const home = await createTempHome("http-conn");
    homes.push(home);
    const file = join(home.beaHome, "http", "connection.json");
    await writeConnectionFile(file, sample("run-a"));
    expect(await readConnectionFile(file)).toEqual(sample("run-a"));
    expect((await readFile(file, "utf8")).endsWith("}\n")).toBe(true);
    expect(await readdir(join(home.beaHome, "http"))).toEqual(["connection.json"]);
    if (process.platform !== "win32") {
      expect((await stat(file)).mode & 0o777).toBe(0o600);
      expect((await stat(join(home.beaHome, "http"))).mode & 0o777).toBe(0o700);
    }
    await writeConnectionFile(file, sample("run-b")); // a newer server replaced it
    expect(await removeConnectionFile(file, "run-a")).toBe(false);
    expect(existsSync(file)).toBe(true);
    expect(await removeConnectionFile(file, "run-b")).toBe(true);
    expect(existsSync(file)).toBe(false);
    expect(await removeConnectionFile(file, "run-b")).toBe(false);
  });

  it("treats unreadable or foreign documents as absent", async () => {
    const home = await createTempHome("http-conn");
    homes.push(home);
    expect(await readConnectionFile(join(home.work, "missing.json"))).toBeNull();
  });

  it("decides 'inside the profile' by path components, case-insensitively on Windows", () => {
    expect(isWithinDirectory("C:\\Users\\me\\AppData\\Local\\bea\\http", "C:\\Users\\me", "win32")).toBe(true);
    expect(isWithinDirectory("c:\\users\\ME\\x", "C:\\Users\\me", "win32")).toBe(true);
    expect(isWithinDirectory("C:\\Users\\me", "C:\\Users\\me", "win32")).toBe(true);
    expect(isWithinDirectory("C:\\Users\\me2\\x", "C:\\Users\\me", "win32")).toBe(false);
    expect(isWithinDirectory("C:\\Users\\me\\..\\other", "C:\\Users\\me", "win32")).toBe(false);
    expect(isWithinDirectory("D:\\bea\\http", "C:\\Users\\me", "win32")).toBe(false);
    expect(isWithinDirectory("/home/me/.local/share/bea", "/home/me", "linux")).toBe(true);
    expect(isWithinDirectory("/home/Me/x", "/home/me", "linux")).toBe(false);
  });

  it("refuses a Windows connection file outside the profile; POSIX relies on file modes", () => {
    expect(
      checkConnectionLocation("C:\\Users\\me\\AppData\\Local\\bea\\http\\connection.json", "win32", "C:\\Users\\me"),
    ).toEqual({ ok: true });
    const refused = checkConnectionLocation("D:\\bea\\http\\connection.json", "win32", "C:\\Users\\me");
    expect(refused.ok).toBe(false);
    expect(refused.ok ? "" : refused.message).toMatch(/D:\\bea\\http is outside your user profile/u);
    expect(checkConnectionLocation("/srv/bea/http/connection.json", "linux", "/home/me")).toEqual({ ok: true });
  });
});
