# Base44 Dev Environment

## What this project is

A prompt-injection scanner. Originally a CLI tool (`npm run scan -- <file>`); a
minimal web UI (`src/server.ts` + `src/web/index.html`) was added so it can be
used from the browser preview. The scanner core (`src/scan.ts` → `scanText()`)
is a pure function shared by both the CLI and the web server.

## Running it

```bash
docker compose -f docker-compose.base44.yml up -d
```

- Node 22 (`node:22-slim`) with `tsx` runs `src/server.ts` on port 3000.
- `npm ci` installs dependencies on container startup (bind-mounted source, no rebuild needed for edits).
- `tsx watch` provides live reload on source changes.

## Credentials

- **ANTHROPIC_API_KEY** (optional): enables the Claude judge. Without it the rule
  engine still runs — only the semantic second opinion is disabled. The frontend
  hides the "Add Claude judge" checkbox when the key is absent. Get a key from
  https://console.anthropic.com/settings/keys.

## Key files

| File | Purpose |
|---|---|
| `src/server.ts` | Web UI server (Node http, no framework) |
| `src/web/index.html` | Browser UI (self-contained, no build step) |
| `src/index.ts` | Original CLI entry point |
| `src/scan.ts` | Core scan pipeline — `scanText()` |
| `src/rules.ts` | Rule definitions and matching |
| `src/score.ts` | Scoring + documentation dampener |

## Verifying it works

- `curl http://localhost:3000/api/status` → `{"judgeAvailable": ...}`
- POST to `/api/scan` with `{"text": "..."}` returns a `ScanResult` JSON.
- Browser: paste text, click Scan, see score + findings.
- Tests: `npm test` (node:test + tsx).
