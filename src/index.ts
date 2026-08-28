/** CLI wiring. All behaviour lives in the modules this imports. */

import Anthropic from "@anthropic-ai/sdk";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import { createJudge, DEFAULT_JUDGE_MODEL, type Judge } from "./llm.ts";
import { renderJson, renderText } from "./report.ts";
import { scanText } from "./scan.ts";
import { BANDS } from "./score.ts";
import { loadSources } from "./sources.ts";
import type { RiskBand, ScanResult } from "./types.ts";

const DEFAULT_MAX_BYTES = 1024 * 1024;

const argv = await yargs(hideBin(process.argv))
  .scriptName("prompt-injection-scanner")
  .usage("$0 <target> [options]")
  .command("$0 <target>", "Score text for prompt-injection risk", (y) =>
    y.positional("target", {
      describe: 'File, directory, or "-" for stdin',
      type: "string",
      demandOption: true,
    }),
  )
  .option("llm", {
    type: "boolean",
    default: false,
    describe: "Add a Claude second opinion (needs API credentials)",
  })
  .option("model", {
    type: "string",
    default: DEFAULT_JUDGE_MODEL,
    describe: "Model for the judge",
  })
  .option("json", {
    type: "boolean",
    default: false,
    describe: "Machine-readable output",
  })
  .option("fail-at", {
    type: "string",
    choices: BANDS,
    default: "suspicious",
    describe: "Band at which to exit non-zero",
  })
  .option("max-bytes", {
    type: "number",
    default: DEFAULT_MAX_BYTES,
    describe: "Per-file size cap",
  })
  .option("color", {
    type: "boolean",
    default: undefined,
    describe: "Force ANSI colour (--no-color to disable)",
  })
  .strict()
  .help()
  .parse();

function buildJudge(): Judge | undefined {
  if (!argv.llm) return undefined;
  try {
    return createJudge({ client: new Anthropic(), model: argv.model });
  } catch (err) {
    // No resolvable credentials. Degrade rather than abort: the rule engine
    // still produces a score, and the report says the judge was unavailable.
    const reason = err instanceof Error ? err.message : String(err);
    return async () => ({ status: "unavailable", reason });
  }
}

async function main(): Promise<number> {
  // yargs types a `$0 <target>` positional as unknown; demandOption guarantees
  // it is present. It also binds a bare "-" to the empty string rather than
  // passing it through, so map that back to the stdin sentinel.
  const raw = (argv.target as string | undefined) ?? "";
  const target = raw === "" ? "-" : raw;

  const sources = await loadSources(target, argv.maxBytes);
  if (sources.length === 0) {
    process.stderr.write("no scannable files found\n");
    return 2;
  }

  const judge = buildJudge();
  const results: ScanResult[] = [];
  for (const source of sources) {
    results.push(
      await scanText(source.text, {
        source: source.name,
        truncated: source.truncated,
        judge,
      }),
    );
  }

  const color = argv.color ?? process.stdout.isTTY === true;
  const rendered = argv.json ? renderJson(results) : renderText(results, color);
  process.stdout.write(`${rendered}\n`);

  const threshold = BANDS.indexOf(argv.failAt as RiskBand);
  const worst = Math.max(...results.map((r) => BANDS.indexOf(r.band)));
  return worst >= threshold ? 1 : 0;
}

try {
  process.exitCode = await main();
} catch (err) {
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 2;
}
