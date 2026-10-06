/**
 * Minimal web UI for the prompt-injection scanner.
 *
 * The scanner core (scanText) is a pure function — this just wraps it in a
 * tiny HTTP server so the tool can be used from a browser. No framework, no
 * extra dependencies: Node's built-in http module + the existing scanner
 * modules.
 */

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import Anthropic from "@anthropic-ai/sdk";
import { createJudge, DEFAULT_JUDGE_MODEL, type Judge } from "./llm.ts";
import { scanText } from "./scan.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const htmlPath = join(__dirname, "web", "index.html");

const judgeAvailable = !!process.env.ANTHROPIC_API_KEY;

function buildJudge(model: string): Judge | undefined {
  if (!judgeAvailable) return undefined;
  try {
    return createJudge({ client: new Anthropic(), model });
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    return async () => ({ status: "unavailable", reason });
  }
}

const server = createServer(async (req, res) => {
  // --- static page ---
  if (req.method === "GET" && (req.url === "/" || req.url === "/index.html")) {
    try {
      const html = await readFile(htmlPath, "utf-8");
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(html);
    } catch {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end("Failed to load page");
    }
    return;
  }

  // --- status: tells the frontend whether the Claude judge is wired up ---
  if (req.method === "GET" && req.url === "/api/status") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ judgeAvailable }));
    return;
  }

  // --- scan endpoint ---
  if (req.method === "POST" && req.url === "/api/scan") {
    let body = "";
    for await (const chunk of req) body += chunk;

    let payload: { text?: string; useJudge?: boolean; model?: string };
    try {
      payload = JSON.parse(body);
    } catch {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid JSON body" }));
      return;
    }

    const text = (payload.text ?? "").slice(0, 1024 * 1024);
    if (!text.trim()) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "No text provided" }));
      return;
    }

    const useJudge = payload.useJudge === true && judgeAvailable;
    const model = payload.model || DEFAULT_JUDGE_MODEL;
    const judge = useJudge ? buildJudge(model) : undefined;

    try {
      const result = await scanText(text, { source: "<web input>", judge });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(result));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: message }));
    }
    return;
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});

const port = Number(process.env.PORT) || 3000;
server.listen(port, "0.0.0.0", () => {
  console.log(`prompt-injection-scanner web UI on http://0.0.0.0:${port}`);
  console.log(`Claude judge: ${judgeAvailable ? "available" : "not configured (rule engine only)"}`);
});
