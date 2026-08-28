/**
 * The rule catalog. Data first, matcher second -- adding a rule should mean
 * adding one entry, never touching control flow.
 *
 * Patterns allow a bounded run of whitespace/punctuation between words (`S`),
 * so `ignore-all-previous-instructions` and `ignore, all previous instructions`
 * both match without the pattern becoming unreadable. The bound matters: an
 * unbounded gap would let unrelated words on the same line match each other.
 */

import type { Category, RuleHit, Severity } from "./types.ts";

export interface Rule {
  id: string;
  category: Category;
  severity: Severity;
  description: string;
  pattern: RegExp;
}

/** Bounded separator run: spaces, hyphens, punctuation between words. */
const S = String.raw`[\s\p{P}]{0,4}`;
/** Short filler span, for "<verb> ... <object>" shapes. */
const GAP = String.raw`[^\n]{0,30}?`;

function rule(
  id: string,
  category: Category,
  severity: Severity,
  description: string,
  source: string,
): Rule {
  return { id, category, severity, description, pattern: new RegExp(source, "giu") };
}

export const RULES: Rule[] = [
  // ---- instruction-override ------------------------------------------------
  rule(
    "io-ignore-previous",
    "instruction-override",
    "critical",
    "Tells the model to discard its previous or system instructions",
    String.raw`(?<![\p{L}\p{N}])(ignore|disregard|forget|override|discard|delete)${S}(all|any|the|your)?${S}(previous|prior|above|preceding|earlier|foregoing|initial|original|system)${S}(instructions?|prompts?|rules?|directions?|guidelines?|commands?|context|messages?)`,
  ),
  rule(
    "io-new-instructions",
    "instruction-override",
    "high",
    "Announces a replacement set of instructions",
    String.raw`(?<![\p{L}\p{N}])(new|updated|revised|actual|real|true|secret|additional)\s+(instructions?|task|directive|objective|mission|prompt|rules?)\s*[:\-]`,
  ),
  rule(
    "io-real-task",
    "instruction-override",
    "high",
    "Reframes the model's purpose ('your real task is...')",
    String.raw`(?<![\p{L}\p{N}])your${S}(real|actual|true|new|only|primary)${S}(task|job|goal|purpose|objective|instruction|role)`,
  ),
  rule(
    "io-stop-and",
    "instruction-override",
    "high",
    "Interrupts the current task and substitutes another",
    String.raw`(?<![\p{L}\p{N}])(stop|halt|abandon|cease)${S}(what|whatever|everything|all)${S}(you|you're|you are)?${S}(are|doing|were)`,
  ),

  // ---- role-impersonation --------------------------------------------------
  rule(
    "ri-system-tag",
    "role-impersonation",
    "high",
    "Forged system/instruction markup",
    String.raw`<\/?\s*(system|system[_-]?prompt|instructions?)\s*>|\[\s*\/?\s*(system|inst)\s*\]`,
  ),
  rule(
    "ri-fake-turn",
    "role-impersonation",
    "medium",
    "Injects a fake conversation turn",
    String.raw`^\s{0,8}(system|assistant|human|user)\s*:`,
  ),
  rule(
    "ri-persona",
    "role-impersonation",
    "high",
    "Reassigns the model to an unrestricted persona",
    String.raw`(?<![\p{L}\p{N}])you${S}are${S}(now${S})?(dan|stan|dude|an?${S}(unrestricted|unfiltered|uncensored|jailbroken|amoral)(\s+\w+)?)(?![\p{L}\p{N}])`,
  ),
  rule(
    "ri-pretend-unbound",
    "role-impersonation",
    "medium",
    "Roleplay framing used to shed constraints",
    String.raw`(?<![\p{L}\p{N}])(pretend|act${S}as${S}if|imagine|roleplay)${S}(that${S})?(you)${S}(are|were|have)${S}(no|not|never)(?![\p{L}\p{N}])`,
  ),

  // ---- exfiltration --------------------------------------------------------
  rule(
    "ex-reveal-prompt",
    "exfiltration",
    "critical",
    "Asks the model to disclose its system prompt or instructions",
    String.raw`(?<![\p{L}\p{N}])(reveal|repeat|print|output|show|display|disclose|dump|echo|recite|tell${S}me)${GAP}(system${S}prompt|initial${S}instructions?|original${S}instructions?|your${S}(instructions?|prompt|rules|guidelines|system${S}message))`,
  ),
  rule(
    "ex-credentials",
    "exfiltration",
    "critical",
    "Asks the model to output credentials or environment secrets",
    String.raw`(?<![\p{L}\p{N}])(print|show|reveal|output|send|leak|exfiltrate|dump|list|email)${GAP}(api${S}keys?|secrets?|tokens?|passwords?|credentials?|\.env(?![\p{L}\p{N}])|environment${S}variables?)`,
  ),
  rule(
    "ex-url-smuggle",
    "exfiltration",
    "high",
    "Instructs the model to smuggle data into a URL or link",
    String.raw`(?<![\p{L}\p{N}])(append|encode|embed|include|attach|add)${GAP}(to|in|into)${S}(the${S})?(url|link|query${S}string|image${S}(url|tag)|markdown${S}image)`,
  ),
  rule(
    "ex-image-placeholder",
    "exfiltration",
    "high",
    "Markdown image whose URL interpolates captured data",
    String.raw`!\[[^\]\n]*\]\(\s*https?:\/\/[^)\n]*(\{\{|\$\{|\$\(|%s)`,
  ),

  // ---- tool-hijack ---------------------------------------------------------
  rule(
    "th-shell-pipe",
    "tool-hijack",
    "critical",
    "Pipes a remote download straight into a shell",
    String.raw`(curl|wget)[^\n|]{1,120}\|\s*(sudo\s+)?(ba|z|k)?sh(?![\p{L}\p{N}])`,
  ),
  rule(
    "th-sensitive-path",
    "tool-hijack",
    "critical",
    "Directs the agent at credential files",
    String.raw`(?<![\p{L}\p{N}])(read|cat|open|send|upload|exfiltrate|print|show|copy|access)${GAP}(~\/\.ssh|\.ssh\/|id_rsa|\.aws\/credentials|\.env(?![\p{L}\p{N}])|\.netrc|keychain|credentials\.json)`,
  ),
  rule(
    "th-run-command",
    "tool-hijack",
    "high",
    "Instructs the agent to execute a command",
    String.raw`(?<![\p{L}\p{N}])(run|execute|invoke|eval)${S}(the${S})?(following${S})?(command|shell|bash|script|code)(?![\p{L}\p{N}])`,
  ),
  rule(
    "th-send-data",
    "tool-hijack",
    "high",
    "Instructs the agent to transmit data to an external destination",
    String.raw`(?<![\p{L}\p{N}])(send|post|upload|transmit|email|forward|beacon)${GAP}(to${S})?(https?:\/\/|[\w.-]+@[\w.-]+\.\w{2,})`,
  ),

  // ---- guardrail-evasion ---------------------------------------------------
  rule(
    "ge-no-restrictions",
    "guardrail-evasion",
    "high",
    "Asserts the model has no restrictions",
    String.raw`(?<![\p{L}\p{N}])(you${S}have${S}no|without${S}any|free${S}from|bypass(ing)?${S}(all${S})?|no${S}longer${S}(bound|subject)${S}(by|to))${S}(restrictions?|limitations?|filters?|guidelines?|rules?|safety|guardrails?|policies)`,
  ),
  rule(
    "ge-developer-mode",
    "guardrail-evasion",
    "high",
    "Invokes a fictional unrestricted mode",
    String.raw`(?<![\p{L}\p{N}])((developer|debug|god|admin|root|dan)${S}mode${S}(enabled|on|activated)|enable${S}(developer|debug|god|admin)${S}mode)`,
  ),
  rule(
    "ge-safety-off",
    "guardrail-evasion",
    "high",
    "Claims safety systems are disabled",
    String.raw`(?<![\p{L}\p{N}])(safety|content${S}polic(y|ies)|filters?|moderation|guardrails?)${S}(is|are|has${S}been|have${S}been)?${S}(off|disabled|turned${S}off|deactivated|removed|suspended|lifted)(?![\p{L}\p{N}])`,
  ),
  rule(
    "ge-hypothetical",
    "guardrail-evasion",
    "low",
    "Fiction/test framing commonly used to unlock behaviour",
    String.raw`(?<![\p{L}\p{N}])(hypothetically${S}speaking|in${S}a${S}fictional${S}(world|scenario|setting)|for${S}educational${S}purposes${S}only|this${S}is${S}(just${S})?a${S}test)`,
  ),

  // ---- obfuscation (pattern-detectable; the rest come from SIGNAL_RULES) ----
  rule(
    "ob-spaced-letters",
    "obfuscation",
    "medium",
    "Words split character-by-character to evade matching",
    String.raw`(?:(?<![\p{L}\p{N}])[a-z][\s.\-_*]+){4,}[a-z](?![\p{L}\p{N}])`,
  ),

  // ---- delimiter-breaking --------------------------------------------------
  rule(
    "db-chat-markers",
    "delimiter-breaking",
    "high",
    "Chat-template control tokens used to escape a data block",
    String.raw`<\|\s*(im_start|im_end|endoftext|system|user|assistant|eot_id|start_header_id)\s*\|>|\[\/?INST\]|<\/?s>`,
  ),
  rule(
    "db-wrapper-escape",
    "delimiter-breaking",
    "medium",
    "Closes a wrapper element the content should be inside of",
    String.raw`<\/\s*(document|context|data|untrusted[_-]?(content|input)?|user[_-]?input|input|content)\s*>`,
  ),

  // ---- urgency-authority ---------------------------------------------------
  rule(
    "ua-secrecy",
    "urgency-authority",
    "high",
    "Instructs the model to hide this content from the user",
    String.raw`(?<![\p{L}\p{N}])(do${S}not|don't|never|without)${S}(tell|inform|mention|reveal|disclose|show|notify|alert)${GAP}(the${S})?(user|human|operator|anyone)(?![\p{L}\p{N}])`,
  ),
  rule(
    "ua-override-all",
    "urgency-authority",
    "medium",
    "Claims precedence over prior instructions",
    String.raw`(?<![\p{L}\p{N}])(overrides?|supersedes?|takes?${S}precedence${S}over|trumps?)${S}(all${S})?(prior|previous|other|any|earlier)${S}(instructions?|rules?|prompts?|directives?)`,
  ),
  rule(
    "ua-imperative",
    "urgency-authority",
    "low",
    "Insistent directive phrasing",
    String.raw`(?<![\p{L}\p{N}])(you${S}must(${S}immediately)?|it${S}is${S}(critical|imperative|essential|mandatory)${S}that${S}you)(?![\p{L}\p{N}])`,
  ),
];

/**
 * Rules that aren't regex matches over the source: they're raised by the
 * normalizer and the decoder. Kept here so every rule's id, category, severity,
 * and wording live in exactly one catalog.
 */
export const SIGNAL_RULES: Record<
  string,
  { category: Category; severity: Severity; description: string }
> = {
  "ob-invisible": {
    category: "obfuscation",
    severity: "high",
    description: "Zero-width or bidi control characters hidden in the text",
  },
  "ob-homoglyph": {
    category: "obfuscation",
    severity: "high",
    description: "Non-Latin characters standing in for ASCII letters",
  },
  "ob-leet": {
    category: "obfuscation",
    severity: "low",
    description: "Digit/symbol substitutions inside words",
  },
  "ob-encoded-blob": {
    category: "obfuscation",
    severity: "medium",
    description: "Encoded payload that decodes to readable text",
  },
};

const MAX_EXCERPT = 120;

function excerpt(match: string): string {
  const flat = match.replace(/\s+/g, " ").trim();
  return flat.length > MAX_EXCERPT ? `${flat.slice(0, MAX_EXCERPT)}...` : flat;
}

/** Runs the catalog over normalized lines. Line numbers are 1-indexed. */
export function matchRules(lines: string[]): RuleHit[] {
  const hits: RuleHit[] = [];

  lines.forEach((line, index) => {
    for (const r of RULES) {
      for (const m of line.matchAll(r.pattern)) {
        const text = m[0];
        if (!text) continue;
        hits.push({
          ruleId: r.id,
          category: r.category,
          severity: r.severity,
          description: r.description,
          line: index + 1,
          excerpt: excerpt(text),
        });
      }
    }
  });

  return hits;
}
