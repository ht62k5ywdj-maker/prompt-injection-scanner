/**
 * Pipeline orchestrator. Pure with respect to the filesystem and the network:
 * it takes a string and an optional judge function, so the whole scan is
 * testable without touching either.
 */

import { decodeEmbedded } from "./decode.ts";
import type { Judge } from "./llm.ts";
import { normalize, type Transform } from "./normalize.ts";
import { matchRules, SIGNAL_RULES } from "./rules.ts";
import { scoreRules } from "./score.ts";
import { bandFor } from "./score.ts";
import type { RuleHit, ScanResult } from "./types.ts";

/** Normalizer transforms that are themselves evidence, and their rule ids. */
const TRANSFORM_SIGNALS: Partial<Record<Transform, string>> = {
  "invisible-strip": "ob-invisible",
  "homoglyph-fold": "ob-homoglyph",
  "leet-fold": "ob-leet",
};

/**
 * Decoded content is scanned, but decoded-from-decoded is not. One level
 * catches real payloads; deeper recursion mostly finds noise and invites a
 * decompression-bomb shaped problem.
 */
const MAX_BLOBS = 20;

export interface ScanOptions {
  /** File path, or "<stdin>". */
  source: string;
  truncated?: boolean;
  /** Omit to run rules-only. */
  judge?: Judge;
}

function signalHit(ruleId: string, line: number, excerpt: string): RuleHit | undefined {
  const meta = SIGNAL_RULES[ruleId];
  if (!meta) return undefined;
  return {
    ruleId,
    category: meta.category,
    severity: meta.severity,
    description: meta.description,
    line,
    excerpt,
  };
}

function trimTo(s: string, max = 120): string {
  const flat = s.replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max)}...` : flat;
}

export async function scanText(
  text: string,
  options: ScanOptions,
): Promise<ScanResult> {
  const { lines, originalLines, transforms } = normalize(text);

  const hits: RuleHit[] = matchRules(lines);

  // Obfuscation the normalizer had to undo is itself a signal.
  for (const { transform, line } of transforms) {
    const ruleId = TRANSFORM_SIGNALS[transform];
    if (!ruleId) continue;
    const hit = signalHit(ruleId, line, trimTo(originalLines[line - 1] ?? ""));
    if (hit) hits.push(hit);
  }

  // Encoded payloads: decode from the ORIGINAL lines. Normalization folds
  // leetspeak, which rewrites digits inside a base64 blob and corrupts it.
  for (const blob of decodeEmbedded(originalLines).slice(0, MAX_BLOBS)) {
    const hit = signalHit("ob-encoded-blob", blob.line, trimTo(blob.decoded));
    if (hit) hits.push({ ...hit, viaDecoding: blob.encoding });

    for (const inner of matchRules(normalize(blob.decoded).lines)) {
      hits.push({ ...inner, line: blob.line, viaDecoding: blob.encoding });
    }
  }

  const rules = scoreRules(hits, text);

  const judge = options.judge
    ? await options.judge(text)
    : ({ status: "skipped" } as const);

  // Max-merge: either engine firing is enough. Both sub-scores stay visible in
  // the report so a disagreement is never hidden behind the final number.
  const judgeScore = judge.status === "ok" ? judge.verdict.score : 0;
  const score = Math.max(rules.score, judgeScore);

  return {
    source: options.source,
    score,
    band: bandFor(score),
    rules,
    judge,
    transformsApplied: transforms.map((t) => t.transform),
    truncated: options.truncated ?? false,
  };
}
