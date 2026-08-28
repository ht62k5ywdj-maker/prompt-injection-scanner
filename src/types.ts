/** Shared types for the scanner pipeline. No logic lives here. */

export type Severity = "low" | "medium" | "high" | "critical";

export type Category =
  | "instruction-override"
  | "role-impersonation"
  | "exfiltration"
  | "tool-hijack"
  | "guardrail-evasion"
  | "obfuscation"
  | "delimiter-breaking"
  | "urgency-authority";

export type RiskBand = "clean" | "low" | "suspicious" | "malicious";

/** A single rule match, before aggregation. */
export interface RuleHit {
  ruleId: string;
  category: Category;
  severity: Severity;
  description: string;
  /** 1-indexed line in the original source text. */
  line: number;
  /** The matched text, taken from the normalized line. */
  excerpt: string;
  /** Set when the hit came from decoded content rather than the literal source. */
  viaDecoding?: string;
}

/** Hits of the same rule collapsed into one reported item. */
export interface Finding extends RuleHit {
  occurrences: number;
}

export interface RulesResult {
  score: number;
  band: RiskBand;
  findings: Finding[];
  /** True when the documentation dampener was applied. Surfaced in the report. */
  dampened: boolean;
  /** How many documentation/analysis markers the text showed. */
  documentationSignals: number;
}

/** The judge's structured answer. Mirrors the Zod schema in llm.ts. */
export interface JudgeVerdict {
  score: number;
  categories: string[];
  rationale: string;
  quotes: string[];
}

/**
 * The judge either ran, was never asked, or could not be reached. A scan is
 * still valid in all three cases — the rule engine always produces a score.
 */
export type JudgeOutcome =
  | { status: "ok"; verdict: JudgeVerdict }
  | { status: "skipped" }
  | { status: "unavailable"; reason: string };

export interface ScanResult {
  /** File path, or "<stdin>". */
  source: string;
  /** Final score: the higher of the rule score and the judge score. */
  score: number;
  band: RiskBand;
  rules: RulesResult;
  judge: JudgeOutcome;
  /** Normalization steps that actually changed the text. */
  transformsApplied: string[];
  /** True when the source was cut short by the size cap. */
  truncated: boolean;
}
