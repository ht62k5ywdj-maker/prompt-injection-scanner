/**
 * Turns rule hits into a 0-100 score.
 *
 * Combination is saturating -- 100 * (1 - product of (1 - weight)) -- so many
 * weak hits accumulate without mechanically pinning the score at 100, while a
 * single critical hit still lands high on its own. Repeated hits of the *same*
 * rule are collapsed: a payload repeating one phrase twenty times is not twenty
 * times more malicious.
 */

import type {
  Category,
  Finding,
  RiskBand,
  RuleHit,
  RulesResult,
  Severity,
} from "./types.ts";

const WEIGHTS: Record<Severity, number> = {
  low: 0.12,
  medium: 0.3,
  high: 0.55,
  critical: 0.8,
};

/** Ordered least to most severe; used by --fail-at comparisons. */
export const BANDS: RiskBand[] = ["clean", "low", "suspicious", "malicious"];

const THRESHOLDS: ReadonlyArray<readonly [number, RiskBand]> = [
  [70, "malicious"],
  [40, "suspicious"],
  [20, "low"],
];

export function bandFor(score: number): RiskBand {
  for (const [min, band] of THRESHOLDS) {
    if (score >= min) return band;
  }
  return "clean";
}

/** Hits across several categories corroborate each other. */
const DIVERSITY_MIN_CATEGORIES = 3;
const DIVERSITY_BONUS = 0.15;

/**
 * Markers of a document *about* prompt injection rather than one *performing*
 * it: prose structure plus analysis vocabulary.
 */
const DOC_MARKERS: RegExp[] = [
  /^#{1,6}\s+\S/m,
  /^\s*```/m,
  /(?<![\p{L}])(mitigat\w+|defen[cs]\w+|countermeasure)/giu,
  /(?<![\p{L}])(attacker|adversar\w+|threat\s+model|red[\s-]?team\w*)/giu,
  /(?<![\p{L}])(vulnerab\w+|sanitiz\w+|exploit\w*)/giu,
  /(?<![\p{L}])(for\s+example|e\.g\.|such\s+as|consider\s+the\s+following)/giu,
  /(?<![\p{L}])(security\s+(researcher|team|review)|owasp|cwe-\d+)/giu,
];

const DOC_SIGNAL_THRESHOLD = 4;
const DAMPEN_BASE = 0.55;
const DAMPEN_PER_SIGNAL = 0.03;
const DAMPEN_FLOOR = 0.2;

/**
 * Graduated, not flat: a page with ten analysis markers is far more likely to
 * be a write-up than one that barely clears the threshold. A flat factor left
 * a security article quoting three separate payloads in the suspicious band.
 */
function dampenFactor(signals: number): number {
  return Math.max(DAMPEN_FLOOR, DAMPEN_BASE - DAMPEN_PER_SIGNAL * signals);
}

export function documentationSignals(text: string): number {
  let signals = 0;
  for (const marker of DOC_MARKERS) {
    if (marker.global) {
      const count = [...text.matchAll(marker)].length;
      if (count > 0) signals += Math.min(count, 2);
    } else if (marker.test(text)) {
      signals += 1;
    }
  }
  return signals;
}

/** Collapses repeated hits of one rule into a single finding with a count. */
function collapse(hits: RuleHit[]): Finding[] {
  const byRule = new Map<string, Finding>();
  for (const hit of hits) {
    const key = `${hit.ruleId}:${hit.viaDecoding ?? ""}`;
    const existing = byRule.get(key);
    if (existing) {
      existing.occurrences += 1;
    } else {
      byRule.set(key, { ...hit, occurrences: 1 });
    }
  }
  return [...byRule.values()].sort(
    (a, b) => WEIGHTS[b.severity] - WEIGHTS[a.severity] || a.line - b.line,
  );
}

export function scoreRules(hits: RuleHit[], sourceText: string): RulesResult {
  const findings = collapse(hits);

  let survival = 1;
  for (const f of findings) survival *= 1 - WEIGHTS[f.severity];
  let score = 1 - survival;

  const categories = new Set<Category>(findings.map((f) => f.category));
  if (categories.size >= DIVERSITY_MIN_CATEGORIES) {
    score += (1 - score) * DIVERSITY_BONUS;
  }

  // A technical article quoting "ignore all previous instructions" trips the
  // same critical rule as an actual payload. Dampen when the surrounding text
  // reads like analysis. This is a heuristic and is reported, never silent --
  // text that adopts documentation vocabulary can lower its own score.
  const signals = documentationSignals(sourceText);
  const dampened = signals >= DOC_SIGNAL_THRESHOLD;
  if (dampened) score *= dampenFactor(signals);

  const finalScore = Math.round(score * 100);
  return {
    score: finalScore,
    band: bandFor(finalScore),
    findings,
    dampened,
    documentationSignals: signals,
  };
}
