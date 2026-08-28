/**
 * Renders a scan into a self-contained, offline HTML report. Presentation
 * only -- exactly like report.ts, just a different medium.
 *
 * SECURITY NOTE: every finding excerpt, judge quote, and reason string in a
 * ScanResult is adversarial input by definition -- that's what this tool
 * scans for. Nothing dynamic is interpolated into the template without going
 * through escapeHtml() first, or a payload like `<script>` in a prompt could
 * execute in the report meant to warn about it.
 */

import type { Finding, JudgeOutcome, RiskBand, ScanResult, Severity } from "./types.ts";

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => {
    switch (c) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      default:
        return "&#39;";
    }
  });
}

export type Grade = "A" | "B" | "C" | "D" | "F";

/**
 * Cosmetic only -- does not touch score.ts's real thresholds. clean/low/
 * malicious map 1:1 onto A/B/F exactly as the tool already scores them; the
 * wide "suspicious" band (40-69) is split into a C/D pair purely so the
 * letter grade has five rungs instead of the engine's four bands.
 */
export function gradeFor(score: number): Grade {
  if (score >= 70) return "F";
  if (score >= 55) return "D";
  if (score >= 40) return "C";
  if (score >= 20) return "B";
  return "A";
}

const BAND_CLASS: Record<RiskBand, string> = {
  clean: "tone-good",
  low: "tone-good",
  suspicious: "tone-warn",
  malicious: "tone-bad",
};

const GRADE_CLASS: Record<Grade, string> = {
  A: "tone-good",
  B: "tone-good",
  C: "tone-warn",
  D: "tone-warn",
  F: "tone-bad",
};

const SEVERITY_CLASS: Record<Severity, string> = {
  low: "tone-dim",
  medium: "tone-warn",
  high: "tone-warn",
  critical: "tone-bad",
};

function badge(text: string, toneClass: string): string {
  return `<span class="badge ${toneClass}">${escapeHtml(text)}</span>`;
}

function slugFor(index: number): string {
  return `file-${index}`;
}

function renderFindings(findings: Finding[]): string {
  if (findings.length === 0) {
    return `<p class="dim">no rule findings</p>`;
  }
  const rows = findings
    .map((f) => {
      const via = f.viaDecoding
        ? ` <span class="tag">via ${escapeHtml(f.viaDecoding)}</span>`
        : "";
      const times = f.occurrences > 1 ? ` <span class="tag">×${f.occurrences}</span>` : "";
      return `<tr>
        <td>${badge(f.severity, SEVERITY_CLASS[f.severity])}</td>
        <td>${escapeHtml(f.category)}</td>
        <td>${f.line}</td>
        <td><code>${escapeHtml(f.ruleId)}</code>${via}${times}</td>
        <td>${escapeHtml(f.description)}</td>
        <td><code>${escapeHtml(f.excerpt)}</code></td>
      </tr>`;
    })
    .join("\n");
  return `<table class="findings">
    <thead><tr><th>Severity</th><th>Category</th><th>Line</th><th>Rule</th><th>Description</th><th>Excerpt</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function renderJudge(judge: JudgeOutcome): string {
  if (judge.status !== "ok") return "";
  const v = judge.verdict;
  const categories =
    v.categories.length > 0
      ? `<p class="dim">categories: ${escapeHtml(v.categories.join(", "))}</p>`
      : "";
  const quotes = v.quotes
    .slice(0, 5)
    .map((q) => `<li>${escapeHtml(q.replace(/\s+/g, " ").slice(0, 120))}</li>`)
    .join("");
  return `<div class="judge">
    <p><strong>Judge:</strong> ${escapeHtml(v.rationale)}</p>
    ${categories}
    ${quotes ? `<ul>${quotes}</ul>` : ""}
  </div>`;
}

function renderNotes(result: ScanResult): string {
  const notes: string[] = [];
  if (result.truncated) {
    notes.push(`<p class="note tone-warn">! input truncated at the size cap; scan is partial</p>`);
  }
  if (result.rules.dampened) {
    notes.push(
      `<p class="note dim">i documentation context detected (${result.rules.documentationSignals} markers); rule score dampened</p>`,
    );
  }
  if (result.judge.status === "unavailable") {
    notes.push(
      `<p class="note tone-warn">! judge unavailable: ${escapeHtml(result.judge.reason)}</p>`,
    );
  }
  return notes.join("\n");
}

function scoreSummary(result: ScanResult): string {
  const parts = [`rules ${result.rules.score}`];
  if (result.judge.status === "ok") parts.push(`judge ${result.judge.verdict.score}`);
  else if (result.judge.status === "unavailable") parts.push("judge unavailable");
  return escapeHtml(`(${parts.join(", ")})`);
}

function renderDetail(result: ScanResult, index: number): string {
  const grade = gradeFor(result.score);
  return `<article id="${slugFor(index)}" class="file">
    <h2>${escapeHtml(result.source)}</h2>
    <p class="score-line">
      ${badge(grade, GRADE_CLASS[grade])}
      ${badge(`${result.score}/100 ${result.band.toUpperCase()}`, BAND_CLASS[result.band])}
      <span class="dim">${scoreSummary(result)}</span>
    </p>
    ${renderNotes(result)}
    <h3>Findings</h3>
    ${renderFindings(result.rules.findings)}
    ${renderJudge(result.judge)}
  </article>`;
}

function renderSummaryRow(result: ScanResult, index: number): string {
  const grade = gradeFor(result.score);
  return `<tr>
    <td>${badge(grade, GRADE_CLASS[grade])}</td>
    <td>${result.score}</td>
    <td>${badge(result.band, BAND_CLASS[result.band])}</td>
    <td><a href="#${slugFor(index)}">${escapeHtml(result.source)}</a></td>
    <td>${result.rules.findings.length}</td>
  </tr>`;
}

function renderBandCounts(results: ScanResult[]): string {
  const counts: Record<RiskBand, number> = { clean: 0, low: 0, suspicious: 0, malicious: 0 };
  for (const r of results) counts[r.band] += 1;
  return (Object.keys(counts) as RiskBand[])
    .map((band) => `<span class="stat ${BAND_CLASS[band]}">${counts[band]} ${band}</span>`)
    .join(" ");
}

const LEGEND = `<details class="legend">
  <summary>How scoring works</summary>
  <p>The rule engine scores 0-100. A score of 0-19 is <strong>clean</strong>,
  20-39 is <strong>low</strong>, 40-69 is <strong>suspicious</strong>, and
  70-100 is <strong>malicious</strong>. Many weak hits accumulate; a single
  critical hit can land high on its own. The letter grade on this report is a
  cosmetic re-slicing of those same bands: A (0-19), B (20-39), C (40-54),
  D (55-69), F (70-100) -- A is safest, F is most dangerous.</p>
  <p>When the optional Claude judge runs, the final score is the
  <strong>higher</strong> of the rule score and the judge score. A
  "dampened" note means the text matched documentation vocabulary (an
  article <em>about</em> prompt injection, not one performing it) and its
  rule score was lowered accordingly -- always reported, never silent.</p>
</details>`;

const STYLE = `<style>
  :root {
    --bg: #ffffff;
    --fg: #1a1a1a;
    --dim: #6b7280;
    --border: #e5e7eb;
    --surface: #f9fafb;
    --good-bg: #dcfce7; --good-fg: #166534;
    --warn-bg: #fef3c7; --warn-fg: #92400e;
    --bad-bg: #fee2e2; --bad-fg: #991b1b;
    --dim-bg: #f3f4f6; --dim-fg: #4b5563;
    --link: #2563eb;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0f1115;
      --fg: #e5e7eb;
      --dim: #9ca3af;
      --border: #2a2e37;
      --surface: #171a21;
      --good-bg: #14532d; --good-fg: #bbf7d0;
      --warn-bg: #78350f; --warn-fg: #fde68a;
      --bad-bg: #7f1d1d; --bad-fg: #fecaca;
      --dim-bg: #1f2430; --dim-fg: #d1d5db;
      --link: #93c5fd;
    }
  }
  * { box-sizing: border-box; }
  body { background: var(--bg); color: var(--fg); margin: 0; padding: 2rem; line-height: 1.5; }
  h1 { margin-bottom: 0.25rem; }
  .meta { color: var(--dim); margin-top: 0; }
  a { color: var(--link); }
  table { border-collapse: collapse; width: 100%; margin: 0.75rem 0 1.5rem; }
  th, td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { color: var(--dim); font-weight: 600; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.02em; }
  code { background: var(--surface); border: 1px solid var(--border); border-radius: 3px; padding: 0.1rem 0.35rem; font-size: 0.9em; white-space: pre-wrap; word-break: break-word; }
  .badge { display: inline-block; padding: 0.15rem 0.55rem; border-radius: 999px; font-weight: 600; font-size: 0.85rem; }
  .tag { display: inline-block; background: var(--dim-bg); color: var(--dim-fg); border-radius: 3px; padding: 0.05rem 0.35rem; font-size: 0.8em; }
  .tone-good { background: var(--good-bg); color: var(--good-fg); }
  .tone-warn { background: var(--warn-bg); color: var(--warn-fg); }
  .tone-bad { background: var(--bad-bg); color: var(--bad-fg); }
  .tone-dim { background: var(--dim-bg); color: var(--dim-fg); }
  .dim { color: var(--dim); }
  .note { margin: 0.25rem 0; }
  .stats { margin: 0.5rem 0 1.25rem; }
  .stat { margin-right: 0.5rem; padding: 0.2rem 0.6rem; border-radius: 6px; font-size: 0.9rem; }
  .legend { margin: 1rem 0 1.5rem; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 0.75rem 1rem; }
  .legend summary { cursor: pointer; font-weight: 600; }
  .file { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1.5rem; background: var(--surface); }
  .file h2 { margin-top: 0; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 1rem; word-break: break-all; }
  .score-line { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
  .judge { margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px dashed var(--border); }
  footer { margin-top: 2rem; color: var(--dim); font-size: 0.85rem; }
</style>`;

export function renderHtml(results: ScanResult[]): string {
  const ranked = [...results].sort((a, b) => b.score - a.score);
  const generatedAt = new Date().toISOString();
  const version = process.env.npm_package_version;

  const summaryTable = `<table class="summary">
    <thead><tr><th>Grade</th><th>Score</th><th>Band</th><th>Source</th><th>Findings</th></tr></thead>
    <tbody>${ranked.map((r, i) => renderSummaryRow(r, i)).join("\n")}</tbody>
  </table>`;

  const details = ranked.map((r, i) => renderDetail(r, i)).join("\n");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Prompt Injection Scan Report</title>
${STYLE}
</head>
<body>
<header>
  <h1>Prompt Injection Scan Report</h1>
  <p class="meta">Generated ${escapeHtml(generatedAt)} &middot; ${ranked.length} file${ranked.length === 1 ? "" : "s"} scanned</p>
</header>
${LEGEND}
<section class="summary">
  <div class="stats">${renderBandCounts(ranked)}</div>
  ${summaryTable}
</section>
<section class="details">
  ${details}
</section>
<footer>
  <p>prompt-injection-scanner${version ? ` v${escapeHtml(version)}` : ""}</p>
</footer>
</body>
</html>`;
}
