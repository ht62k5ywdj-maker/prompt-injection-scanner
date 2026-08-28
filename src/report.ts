/** Renders a scan into a terminal report or JSON. Presentation only. */

import type { RiskBand, ScanResult, Severity } from "./types.ts";

/** Built at runtime so no raw escape bytes sit in the source. */
const CSI = `${String.fromCharCode(27)}[`;

const ANSI = {
  reset: `${CSI}0m`,
  bold: `${CSI}1m`,
  dim: `${CSI}2m`,
  red: `${CSI}31m`,
  yellow: `${CSI}33m`,
  green: `${CSI}32m`,
  cyan: `${CSI}36m`,
} as const;

type Code = keyof typeof ANSI;
type Paint = (s: string, ...codes: Code[]) => string;

function painter(color: boolean): Paint {
  if (!color) return (s) => s;
  return (s, ...codes) => `${codes.map((c) => ANSI[c]).join("")}${s}${ANSI.reset}`;
}

const BAND_COLOR: Record<RiskBand, Code> = {
  clean: "green",
  low: "green",
  suspicious: "yellow",
  malicious: "red",
};

const SEVERITY_COLOR: Record<Severity, Code> = {
  low: "dim",
  medium: "yellow",
  high: "yellow",
  critical: "red",
};

function scoreLine(result: ScanResult, paint: Paint): string {
  const band = result.band.toUpperCase();
  const head = paint(`${result.score}/100  ${band}`, BAND_COLOR[result.band], "bold");
  const parts = [`rules ${result.rules.score}`];
  if (result.judge.status === "ok") parts.push(`judge ${result.judge.verdict.score}`);
  else if (result.judge.status === "unavailable") parts.push("judge unavailable");
  return `  ${head}  ${paint(`(${parts.join(", ")})`, "dim")}`;
}

function renderOne(result: ScanResult, paint: Paint): string[] {
  const out: string[] = [paint(result.source, "bold", "cyan"), scoreLine(result, paint)];

  if (result.truncated) {
    out.push(paint("  ! input truncated at the size cap; scan is partial", "yellow"));
  }
  if (result.rules.dampened) {
    out.push(
      paint(
        `  i documentation context detected (${result.rules.documentationSignals} markers); rule score dampened`,
        "dim",
      ),
    );
  }
  if (result.judge.status === "unavailable") {
    out.push(paint(`  ! judge unavailable: ${result.judge.reason}`, "yellow"));
  }

  if (result.rules.findings.length === 0) {
    out.push(paint("  no rule findings", "dim"));
  } else {
    out.push("  findings:");
    for (const f of result.rules.findings) {
      const tag = paint(`[${f.severity}]`, SEVERITY_COLOR[f.severity]);
      const via = f.viaDecoding ? paint(` via ${f.viaDecoding}`, "dim") : "";
      const times = f.occurrences > 1 ? paint(` x${f.occurrences}`, "dim") : "";
      const where = paint(`line ${f.line}`, "dim");
      out.push(`    ${tag} ${f.category}  ${where}  ${f.ruleId}${via}${times}`);
      out.push(`      ${paint(f.description, "dim")}`);
      out.push(`      ${paint("> ", "dim")}${f.excerpt}`);
    }
  }

  if (result.judge.status === "ok") {
    const v = result.judge.verdict;
    out.push(`  judge: ${paint(v.rationale, "dim")}`);
    if (v.categories.length > 0) {
      out.push(`    categories: ${paint(v.categories.join(", "), "dim")}`);
    }
    for (const q of v.quotes.slice(0, 5)) {
      out.push(`    ${paint("> ", "dim")}${q.replace(/\s+/g, " ").slice(0, 120)}`);
    }
  }

  return out;
}

export function renderText(results: ScanResult[], color: boolean): string {
  const paint = painter(color);
  const ranked = [...results].sort((a, b) => b.score - a.score);
  const out: string[] = [];

  if (ranked.length > 1) {
    out.push(paint(`Scanned ${ranked.length} files, worst first:`, "bold"), "");
    for (const r of ranked) {
      const band = paint(r.band.padEnd(10), BAND_COLOR[r.band]);
      out.push(`  ${String(r.score).padStart(3)}  ${band}  ${r.source}`);
    }
    out.push("");
  }

  for (const r of ranked) {
    out.push(...renderOne(r, paint), "");
  }

  return out.join("\n").trimEnd();
}

export function renderJson(results: ScanResult[]): string {
  return JSON.stringify(results, null, 2);
}
