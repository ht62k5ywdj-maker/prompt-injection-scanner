# prompt-injection-scanner

Reads a prompt and scores how likely it is to be a prompt-injection attempt.

A deterministic rule engine always runs, offline and free. An optional Claude
judge adds a semantic second opinion for phrasings the regexes miss. The final
score is the **higher of the two** — a security tool should fail loud, and both
sub-scores stay visible so a disagreement is never hidden.

## Usage

```bash
npm install

npm run scan -- suspicious.txt              # one file
npm run scan -- ./prompts/                  # a directory, ranked worst first
cat suspicious.txt | npm run scan -- -      # stdin
npm run scan -- suspicious.txt --json       # machine-readable
npm run scan -- suspicious.txt --llm        # add the Claude judge
```

A shell alias is the convenient way to use it from anywhere:

```bash
alias pinj='npm --prefix ~/Scripts/claude/prompt-injection-scanner run --silent scan --'
```

### Options

| Flag | Default | Purpose |
|---|---|---|
| `<target>` | — | file, directory, or `-` for stdin |
| `--llm` | `false` | add the Claude judge (needs API credentials) |
| `--model` | `claude-opus-5` | judge model |
| `--json` | `false` | machine-readable output |
| `--fail-at` | `suspicious` | band at which to exit non-zero |
| `--max-bytes` | `1048576` | per-file size cap |
| `--no-color` | auto | disable ANSI colour |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | worst result is below `--fail-at` |
| `1` | worst result is at or above `--fail-at` |
| `2` | operational error (unreadable target, no scannable files) |

## Scoring

Score is 0–100, mapped to four bands:

| Band | Range |
|---|---|
| `clean` | 0–19 |
| `low` | 20–39 |
| `suspicious` | 40–69 |
| `malicious` | 70–100 |

Rule hits combine by saturation — `100 × (1 − Π(1 − weight))` — so many weak
hits accumulate without mechanically pinning the score at 100, while a single
critical hit still lands high on its own. Repeated hits of the *same* rule
collapse into one finding with a count: a payload repeating one phrase twenty
times is not twenty times more malicious. Hits spanning three or more categories
get a small corroboration bonus.

### Rule categories

| Category | Catches |
|---|---|
| `instruction-override` | "ignore all previous instructions", task reframing |
| `role-impersonation` | forged `<system>` markup, fake turns, persona reassignment |
| `exfiltration` | system-prompt disclosure, credential dumps, URL smuggling |
| `tool-hijack` | `curl … \| sh`, credential-file reads, data transmission |
| `guardrail-evasion` | "developer mode", "you have no restrictions" |
| `obfuscation` | zero-width characters, homoglyphs, leetspeak, encoded blobs |
| `delimiter-breaking` | chat-template control tokens, wrapper escapes |
| `urgency-authority` | "do not tell the user", precedence claims |

### Obfuscation handling

Text is normalized before matching: NFKC, zero-width and bidi stripping,
Cyrillic/Greek homoglyph folding, and leetspeak folding inside words. Encoded
payloads (base64, hex, percent, HTML entities, `\u` escapes) are decoded from
the **raw** text and re-scanned one level deep, so a base64-wrapped payload is
caught. Findings from decoded content are marked `via base64` and friends.

### The documentation dampener

A technical article about prompt injection quotes real payloads and trips the
same rules an actual attack does. When the surrounding text reads like analysis
— markdown structure plus vocabulary like *mitigation*, *attacker*,
*vulnerability*, *OWASP* — the rule score is dampened, more so as the evidence
strengthens. The report always says when this happened; it is never silent.

**This is a heuristic and it cuts both ways.** Text that adopts documentation
vocabulary can lower its own score. If that matters for your use case, run with
`--llm`, which reasons about context directly and is not dampened.

## The judge

The scanned text is hostile input to the judge call too. It is wrapped in a
per-call random nonce tag, and the system prompt states that the block is data
and never instruction — including that content telling the grader what score to
return is itself evidence of injection. `fixtures/judge-bait.txt` exercises this.

If the judge refuses, errors, or has no credentials, the scan degrades to
rules-only and says so in the report. A scan never fails because the judge was
unavailable.

Credentials resolve the normal SDK way: `ANTHROPIC_API_KEY`, or an
`ant auth login` profile.

## Development

```bash
npm test        # node --test, 51 tests
npm run typecheck
```

`src/scan.ts` is pure over a string with an injectable judge, so the whole
pipeline is testable without the filesystem or the network.

## Limitations

This is a heuristic aid, not a guarantee.

- The rule catalog matches known shapes; novel phrasings will slip past it.
- The judge is non-deterministic and costs money per scan.
- The documentation dampener can be gamed, as described above.
- Decoding goes one level deep; a doubly-encoded payload is flagged as an
  encoded blob but its contents are not scanned.

Do not use the exit code as your only control on an untrusted-input path.
