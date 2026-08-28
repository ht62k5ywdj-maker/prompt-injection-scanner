/**
 * Folds cosmetic obfuscation so the rule catalog cannot be dodged by
 * homoglyphs, zero-width padding, or leetspeak.
 *
 * Deliberately NOT handled here: l e t t e r  s p a c i n g. Collapsing it
 * destroys word boundaries ("i g n o r e a l l" -> "ignoreallprevious", which
 * then matches no phrase) and mangles ordinary prose ("a b i g fan" -> "abig").
 * Separator insertion is handled instead by the tolerant phrase compiler in
 * rules.ts, which matches the text as written.
 *
 * INVARIANT: every transform operates within a single line. Line count and
 * ordering are preserved, so a finding on normalized line N can cite original
 * line N without maintaining a character offset map. normalize.test.ts
 * enforces this.
 */

/** Zero-width, bidi-control, and other invisible characters used to split words. */
const INVISIBLE =
  /[­᠎​-‏‪-‮⁠-⁤﻿]/g;

/** Cyrillic and Greek characters that render as ASCII letters. */
const HOMOGLYPHS: Record<string, string> = {
  // Cyrillic lowercase
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
  "у": "y", "х": "x", "і": "i", "ѕ": "s", "ј": "j",
  "һ": "h", "ԁ": "d", "ԛ": "q",
  // Cyrillic uppercase
  "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
  "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
  "У": "Y", "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J",
  // Greek lowercase
  "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
  "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
  // Greek uppercase
  "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
  "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
  "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
};

/** Leet substitutions, applied only inside tokens that already contain letters. */
const LEET: Record<string, string> = {
  "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
  "@": "a", "$": "s", "!": "i",
};

export type Transform =
  | "nfkc"
  | "invisible-strip"
  | "homoglyph-fold"
  | "leet-fold";

/** A transform that fired, and the first line it fired on. */
export interface AppliedTransform {
  transform: Transform;
  line: number;
}

export interface NormalizedText {
  /** Normalized lines. Always the same length as originalLines. */
  lines: string[];
  originalLines: string[];
  /** Only the transforms that actually changed something, with first line. */
  transforms: AppliedTransform[];
}

function foldHomoglyphs(line: string): string {
  let out = "";
  for (const ch of line) out += HOMOGLYPHS[ch] ?? ch;
  return out;
}

/**
 * Leet-folds only characters sitting in a token that already contains an ASCII
 * letter. That keeps `ign0re` -> `ignore` while leaving `2024` and `$4.99`
 * alone, which would otherwise turn into noise and trip rules on benign text.
 * Long base64/hex-looking tokens are skipped too -- folding their digits
 * corrupts a payload that decode.ts would otherwise recover.
 */
const ENCODED_TOKEN = /^[A-Za-z0-9+/=]{20,}$/;

function foldLeet(line: string): string {
  return line.replace(/\S+/g, (token) => {
    if (!/[a-zA-Z]/.test(token)) return token;
    if (ENCODED_TOKEN.test(token)) return token;
    let out = "";
    for (const ch of token) out += LEET[ch] ?? ch;
    return out;
  });
}

export function normalize(text: string): NormalizedText {
  const originalLines = text.split("\n");
  const firstSeen = new Map<Transform, number>();

  const lines = originalLines.map((original, index) => {
    const applied = {
      add(t: Transform) {
        if (!firstSeen.has(t)) firstSeen.set(t, index + 1);
      },
    };

    let line = original.normalize("NFKC");
    if (line !== original) applied.add("nfkc");

    const stripped = line.replace(INVISIBLE, "");
    if (stripped !== line) applied.add("invisible-strip");
    line = stripped;

    const folded = foldHomoglyphs(line);
    if (folded !== line) applied.add("homoglyph-fold");
    line = folded;

    const leeted = foldLeet(line);
    if (leeted !== line) applied.add("leet-fold");
    line = leeted;

    return line;
  });

  return {
    lines,
    originalLines,
    transforms: [...firstSeen].map(([transform, line]) => ({ transform, line })),
  };
}
