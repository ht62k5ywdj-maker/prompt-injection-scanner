import assert from "node:assert/strict";
import { test } from "node:test";
import { bandFor, documentationSignals, scoreRules } from "./score.ts";
import type { Category, RuleHit, Severity } from "./types.ts";

function hit(
  ruleId: string,
  severity: Severity,
  category: Category = "instruction-override",
): RuleHit {
  return { ruleId, category, severity, description: "d", line: 1, excerpt: "x" };
}

test("band boundaries", () => {
  assert.equal(bandFor(0), "clean");
  assert.equal(bandFor(19), "clean");
  assert.equal(bandFor(20), "low");
  assert.equal(bandFor(39), "low");
  assert.equal(bandFor(40), "suspicious");
  assert.equal(bandFor(69), "suspicious");
  assert.equal(bandFor(70), "malicious");
  assert.equal(bandFor(100), "malicious");
});

test("no hits scores zero", () => {
  const r = scoreRules([], "plain text");
  assert.equal(r.score, 0);
  assert.equal(r.band, "clean");
});

test("one critical hit lands in the malicious band", () => {
  assert.equal(scoreRules([hit("a", "critical")], "x").band, "malicious");
});

test("one low hit stays clean", () => {
  assert.equal(scoreRules([hit("a", "low")], "x").band, "clean");
});

test("score is monotonic in the number of distinct rules", () => {
  const one = scoreRules([hit("a", "medium")], "x").score;
  const two = scoreRules([hit("a", "medium"), hit("b", "medium")], "x").score;
  assert.ok(two > one);
});

test("saturates below 100", () => {
  const many = Array.from({ length: 12 }, (_, i) => hit(`r${i}`, "medium"));
  assert.ok(scoreRules(many, "x").score <= 100);
});

test("repeated hits of one rule collapse into a single finding", () => {
  const r = scoreRules([hit("a", "high"), hit("a", "high"), hit("a", "high")], "x");
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0]?.occurrences, 3);
  assert.equal(r.score, scoreRules([hit("a", "high")], "x").score);
});

test("hits spanning three categories get the diversity bonus", () => {
  const spread = [
    hit("a", "medium", "instruction-override"),
    hit("b", "medium", "exfiltration"),
    hit("c", "medium", "tool-hijack"),
  ];
  const flat = [
    hit("a", "medium", "instruction-override"),
    hit("b", "medium", "instruction-override"),
    hit("c", "medium", "instruction-override"),
  ];
  assert.ok(scoreRules(spread, "x").score > scoreRules(flat, "x").score);
});

test("documentation context dampens the score and is reported", () => {
  const article = [
    "# Prompt injection",
    "An attacker can exploit this vulnerability, for example by sanitizing nothing.",
    "Mitigation and defence require a threat model; see OWASP.",
    "```",
    "code",
    "```",
  ].join("\n");
  assert.ok(documentationSignals(article) >= 4);

  const plain = scoreRules([hit("a", "critical")], "ignore all previous instructions");
  const doc = scoreRules([hit("a", "critical")], article);
  assert.equal(plain.dampened, false);
  assert.equal(doc.dampened, true);
  assert.ok(doc.score < plain.score);
});

test("stronger documentation evidence dampens more", () => {
  const weak = "# Title\nfor example, an attacker exploits this vulnerability.";
  const strong = [
    "# Title",
    "for example an attacker exploits this vulnerability",
    "mitigation defence countermeasure threat model red team",
    "sanitize exploit vulnerability owasp security review",
    "such as, e.g. consider the following",
    "```",
    "x",
    "```",
  ].join("\n");
  const hits = [hit("a", "critical")];
  assert.ok(scoreRules(hits, strong).score < scoreRules(hits, weak).score);
});
