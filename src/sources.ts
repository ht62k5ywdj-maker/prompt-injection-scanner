/** Resolves a CLI target into scannable text: a file, stdin, or a directory. */

import { readdir, readFile, stat } from "node:fs/promises";
import { join, extname, basename } from "node:path";

export interface Source {
  name: string;
  text: string;
  truncated: boolean;
}

/** Extensions worth scanning. Anything else in a directory walk is skipped. */
const TEXT_EXTENSIONS = new Set([
  ".txt", ".text", ".md", ".markdown", ".rst", ".prompt", ".tpl",
  ".json", ".yaml", ".yml", ".xml", ".html", ".htm", ".csv", ".tsv", ".log",
]);

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".venv", "venv", "__pycache__",
  ".next", "coverage", ".cache",
]);

/** A NUL byte in the first block is the cheap, reliable binary tell. */
function isBinary(buf: Buffer): boolean {
  return buf.subarray(0, 4096).includes(0);
}

async function readCapped(path: string, maxBytes: number): Promise<Source | undefined> {
  const buf = await readFile(path);
  if (isBinary(buf)) return undefined;
  const truncated = buf.length > maxBytes;
  return {
    name: path,
    text: buf.subarray(0, maxBytes).toString("utf8"),
    truncated,
  };
}

async function readStdin(maxBytes: number): Promise<Source> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    const buf = Buffer.from(chunk);
    chunks.push(buf);
    total += buf.length;
    if (total > maxBytes) break;
  }
  const joined = Buffer.concat(chunks);
  return {
    name: "<stdin>",
    text: joined.subarray(0, maxBytes).toString("utf8"),
    truncated: joined.length > maxBytes,
  };
}

async function walk(dir: string, maxBytes: number): Promise<Source[]> {
  const out: Source[] = [];
  const entries = await readdir(dir, { withFileTypes: true });

  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name) || entry.name.startsWith(".")) continue;
      out.push(...(await walk(path, maxBytes)));
      continue;
    }
    if (!entry.isFile()) continue;
    const ext = extname(entry.name).toLowerCase();
    // Extensionless files (READMEs, prompt files) are worth reading too.
    if (ext !== "" && !TEXT_EXTENSIONS.has(ext)) continue;
    if (basename(entry.name).startsWith(".")) continue;
    const source = await readCapped(path, maxBytes);
    if (source) out.push(source);
  }

  return out.sort((a, b) => a.name.localeCompare(b.name));
}

export async function loadSources(
  target: string,
  maxBytes: number,
): Promise<Source[]> {
  if (target === "-") return [await readStdin(maxBytes)];

  const info = await stat(target);
  if (info.isDirectory()) return walk(target, maxBytes);

  const source = await readCapped(target, maxBytes);
  if (!source) throw new Error(`${target} looks like a binary file`);
  return [source];
}
