/**
 * Surfaces payloads hidden behind an encoding layer. Injections are routinely
 * base64'd to slip past literal pattern matching, so scan.ts re-scans whatever
 * comes back out of here (once -- see DECODE_DEPTH in scan.ts).
 *
 * Every decoder is guarded: a candidate only counts if it decodes to plausible
 * text. Without that, long ordinary words ("supercalifragilistic...") and hex
 * colour lists get reported as encoded payloads.
 */

export type Encoding =
  | "base64"
  | "hex"
  | "percent"
  | "html-entity"
  | "unicode-escape";

export interface DecodedBlob {
  encoding: Encoding;
  /** 1-indexed line in the original source where the blob was found. */
  line: number;
  /** The decoded text, ready to be re-scanned. */
  decoded: string;
}

/**
 * Does this look like human-readable text rather than binary noise? This is the
 * guard that keeps ordinary words from being reported as base64 payloads --
 * they decode to bytes that fail the printable-ratio check.
 */
function looksLikeText(s: string): boolean {
  if (s.length < 8) return false;
  let printable = 0;
  for (const ch of s) {
    const c = ch.codePointAt(0) ?? 0;
    if ((c >= 0x20 && c <= 0x7e) || c === 0x09 || c === 0x0a || c === 0x0d) {
      printable++;
    }
  }
  if (printable / s.length < 0.85) return false;
  // Require at least one run of letters; base64 of random bytes rarely has one.
  return /[a-z]{3}/i.test(s);
}

function decodeBase64(candidate: string): string | undefined {
  // Reject strings whose length can't be valid base64.
  if (candidate.replace(/=+$/, "").length % 4 === 1) return undefined;
  try {
    const buf = Buffer.from(candidate, "base64");
    if (buf.length === 0) return undefined;
    const text = buf.toString("utf8");
    if (text.includes("�")) return undefined; // invalid UTF-8
    return looksLikeText(text) ? text : undefined;
  } catch {
    return undefined;
  }
}

function decodeHex(candidate: string): string | undefined {
  try {
    const text = Buffer.from(candidate, "hex").toString("utf8");
    if (text.includes("�")) return undefined;
    return looksLikeText(text) ? text : undefined;
  } catch {
    return undefined;
  }
}

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", "#39": "'",
};

function decodeEntities(line: string): string | undefined {
  const matches = line.match(/&(#x?[0-9a-f]+|[a-z]+);/gi);
  if (!matches || matches.length < 4) return undefined;
  const decoded = line.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (_full, body: string) => {
    const key = body.toLowerCase();
    if (key.startsWith("#x")) {
      return String.fromCodePoint(parseInt(key.slice(2), 16));
    }
    if (key.startsWith("#")) {
      return String.fromCodePoint(parseInt(key.slice(1), 10));
    }
    return NAMED_ENTITIES[key] ?? _full;
  });
  return decoded === line ? undefined : decoded;
}

function decodePercent(line: string): string | undefined {
  const matches = line.match(/%[0-9a-f]{2}/gi);
  if (!matches || matches.length < 4) return undefined;
  try {
    const decoded = decodeURIComponent(line);
    return decoded === line ? undefined : decoded;
  } catch {
    return undefined;
  }
}

function decodeUnicodeEscapes(line: string): string | undefined {
  const matches = line.match(/\\u\{?[0-9a-f]{2,6}\}?/gi);
  if (!matches || matches.length < 4) return undefined;
  const decoded = line.replace(/\\u\{?([0-9a-f]{2,6})\}?/gi, (full, hex: string) => {
    const cp = parseInt(hex, 16);
    return Number.isFinite(cp) && cp <= 0x10ffff ? String.fromCodePoint(cp) : full;
  });
  return decoded === line ? undefined : decoded;
}

/** Minimum run length before a token is even considered as base64/hex. */
const MIN_BASE64 = 24;
const MIN_HEX = 24; // 12 bytes

export function decodeEmbedded(lines: string[]): DecodedBlob[] {
  const blobs: DecodedBlob[] = [];

  lines.forEach((line, index) => {
    const lineNo = index + 1;

    for (const m of line.matchAll(
      new RegExp(String.raw`[A-Za-z0-9+/]{${MIN_BASE64},}={0,2}`, "g"),
    )) {
      const decoded = decodeBase64(m[0]);
      if (decoded) blobs.push({ encoding: "base64", line: lineNo, decoded });
    }

    for (const m of line.matchAll(
      new RegExp(String.raw`\b(?:[0-9a-fA-F]{2}){${MIN_HEX / 2},}\b`, "g"),
    )) {
      const decoded = decodeHex(m[0]);
      if (decoded) blobs.push({ encoding: "hex", line: lineNo, decoded });
    }

    const percent = decodePercent(line);
    if (percent) blobs.push({ encoding: "percent", line: lineNo, decoded: percent });

    const entity = decodeEntities(line);
    if (entity) blobs.push({ encoding: "html-entity", line: lineNo, decoded: entity });

    const escapes = decodeUnicodeEscapes(line);
    if (escapes) {
      blobs.push({ encoding: "unicode-escape", line: lineNo, decoded: escapes });
    }
  });

  return blobs;
}
