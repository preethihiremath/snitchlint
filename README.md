# SnitchLint

**SnitchLint** is a VS Code extension that performs **static application security testing (SAST)** for **JavaScript and TypeScript**. It finds OWASP-aligned vulnerabilities as you type, explains *why* they matter, and suggests **production-ready secure fixes**—without sending your code to a cloud API by default.

[![Version](https://img.shields.io/badge/version-0.2.0-blue)](package.json)
[![VS Code](https://img.shields.io/badge/VS%20Code-%5E1.100.0-007ACC)](package.json)

---

## Highlights (v0.2.0)

| Feature | Description |
|--------|-------------|
| **16 security rules** | SQLi, XSS, secrets, command injection, SSRF, path traversal, and more |
| **Taint analysis** | Tracks untrusted input (`req.body`, `req.query`, etc.) to dangerous sinks |
| **Problems panel** | Inline diagnostics with rule IDs and quick fixes |
| **AI Insight panel** | Explains vulnerability, taint flow, OWASP + CWE, before/after fixes |
| **Offline by default** | No API keys; safe for Marketplace and air-gapped environments |
| **Optional local AI** | [Ollama](https://ollama.com) (free, on your machine) or VS Code Language Model API |
| **SARIF export** | Workspace scan for CI (`snitchlint.sarif`) |

---

## Quick start

1. Install or run from source (`F5` Extension Development Host).
2. Open a `.js` / `.ts` file with security issues (see `src/test/fixtures/`).
3. Check the **Problems** panel for SnitchLint findings.
4. Click the **lightbulb** → **SnitchLint: Explain & Suggest Fix**, or run **SnitchLint: Explain Vulnerability & Suggest Fix** from the Command Palette.
5. Review the **AI Insight** webview: explanation, taint flow, CWE, and before/after code.

---

## What it checks

All rules map to **OWASP Top 10 (2021)** and include **CWE** metadata for the AI panel.

| Rule ID | Vulnerability | Technique |
|---------|---------------|-----------|
| `sql-injection` | SQL Injection | Taint → `query` / `execute` / `raw` |
| `xss` | DOM XSS | Taint → `innerHTML` / `document.write` |
| `react-dangerously-set-inner-html` | React XSS | Pattern match |
| `hardcoded-secrets` | Hardcoded credentials | Regex on literals |
| `command-injection` | OS command injection | Taint → `child_process` |
| `insecure-eval-function` | Code injection | `eval` / `new Function` |
| `insecure-deserialization` | Unsafe deserialization | Taint → `JSON.parse` |
| `weak-crypto` | Weak hash | `md5` / `sha1` |
| `unrestricted-file-upload` | Unsafe upload | `multer.single` heuristic |
| `insecure-cookie-flags` | Missing cookie flags | `res.cookie` analysis |
| `csrf-protection` | Missing CSRF | Middleware heuristic |
| `open-redirect` | Open redirect | Taint → `res.redirect` |
| `path-traversal` | Path traversal | Taint → `fs.readFile*` |
| `ssrf` | SSRF | Taint → `fetch` / HTTP clients |
| `jwt-weak-secret` | Weak JWT secret | Literal in `jwt.sign` |
| `sensitive-logging` | Sensitive data in logs | Pattern on log calls |

---

## AI Explanation & Fix Suggestions

### How it works (default — no AI API)

1. **Rules** produce a `Finding` (offsets, message, optional taint flow).
2. **`findingEnricher`** adds CWE, vulnerability type, and taint steps if missing.
3. **`explanationBuilder`** turns the finding into a structured explanation.
4. **`fixSuggestionBuilder`** generates rule-specific **before/after** code.
5. **`AiInsightPanel`** renders a webview; **Apply fix** replaces the line when safe.

This is deterministic static analysis—not a hosted LLM—so it is **private**, **fast**, and **publishable** on the VS Code Marketplace.

### Optional enhancement

```json
{
  "snitchlint.ai.ollamaEnabled": true,
  "snitchlint.ai.ollamaModel": "llama3.2",
  "snitchlint.ai.useVsCodeLm": false
}
```

- **Ollama**: Install locally, run `ollama pull llama3.2`, enable the setting. Data never leaves your machine.
- **VS Code LM**: Uses the Language Model API when you have access (e.g. Copilot). Off by default.

---

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `snitchlint.enabled` | `true` | Master switch |
| `snitchlint.debounceMs` | `400` | Delay after edits before re-scan |
| `snitchlint.logLevel` | `warn` | Output channel verbosity |
| `snitchlint.rules` | `{}` | Per-rule `false` to disable |
| `snitchlint.ai.ollamaEnabled` | `false` | Local Ollama enhancement |
| `snitchlint.ai.ollamaUrl` | `http://127.0.0.1:11434` | Ollama API URL |
| `snitchlint.ai.ollamaModel` | `llama3.2` | Model name |
| `snitchlint.ai.useVsCodeLm` | `false` | VS Code Language Model API |

Example — disable noisy rules:

```json
{
  "snitchlint.rules": {
    "csrf-protection": false
  }
}
```

---

## Commands

| Command | Action |
|---------|--------|
| `SnitchLint: Scan Active File` | Re-run analysis on the open file |
| `SnitchLint: Scan Workspace (SARIF)` | Write `snitchlint.sarif` at workspace root |
| `SnitchLint: Explain Vulnerability & Suggest Fix` | Open AI Insight panel |
| Lightbulb → **Explain & Suggest Fix** | Same, for the selected diagnostic |
| Lightbulb → **Ignore** | Insert `// snitchlint-ignore: <rule-id>` |

Ignore directives: `// snitchlint-ignore: sql-injection` or `// snitchlint-ignore` on the same or previous line.

---

## Architecture (how the code fits together)

```
┌─────────────────────────────────────────────────────────────────┐
│  extension.ts          VS Code entry: events, commands, UI      │
└────────────┬────────────────────────────────────────────────────┘
             │
     ┌───────┴───────┐
     ▼               ▼
┌─────────────┐  ┌──────────────────┐
│ scanner.ts  │  │ aiInsightPanel   │  Webview: explain + fix
│ (engine)    │  │ + explanation/   │
└──────┬──────┘  │   fix builders   │
       │         └──────────────────┘
       │ parse once + TaintAnalyzer
       ▼
┌──────────────────────────────────────┐
│  rules/*.ts  (16 SecurityRule)       │
│  registry.ts → ordered rule list     │
└──────────────────────────────────────┘
       │ Finding[]
       ▼
┌──────────────────────────────────────┐
│  findingEnricher → CWE, taint flow   │
│  vscodeDiagnostics → Problems panel  │
└──────────────────────────────────────┘
```

**Layering principle:** `engine/` and `rules/` have **no `vscode` import**—they are unit-testable without the VS Code host.

See **[vsc-extension-quickstart.md](./vsc-extension-quickstart.md)** for a **file-by-file walkthrough** and contributor setup.

---

## Project layout

| Path | Role |
|------|------|
| `src/extension.ts` | Activation, debounced scan, diagnostics, AI panel, SARIF |
| `src/engine/scanner.ts` | Orchestrates parse → taint → rules → enrich |
| `src/engine/taintAnalyzer.ts` | Monotonic taint propagation (sources → sinks) |
| `src/engine/createSourceFile.ts` | TypeScript AST parse helper |
| `src/rules/*.ts` | One detector per vulnerability class |
| `src/rules/registry.ts` | `allSecurityRules` list |
| `src/rules/findingHelpers.ts` | `buildTaintFinding()` with structured flow |
| `src/metadata/ruleMetadata.ts` | CWE, OWASP labels, “why it matters” text |
| `src/ai/explanationBuilder.ts` | Finding → human explanation |
| `src/ai/fixSuggestionBuilder.ts` | Rule-specific before/after fixes |
| `src/ai/findingEnricher.ts` | Post-scan CWE/taint enrichment |
| `src/ai/optionalAiClient.ts` | Optional Ollama / VS Code LM |
| `src/ui/aiInsightPanel.ts` | Webview UI |
| `src/adapters/vscodeDiagnostics.ts` | Finding → `vscode.Diagnostic` |
| `src/config/` | Settings model + VS Code bridge |
| `src/types/findings.ts` | Core `Finding` type |
| `src/test/` | Unit + integration tests, fixtures |

---

## Testing

**Unit tests** (engine, rules, AI builders — no VS Code UI):

```bash
npm run test:unit
```

**Integration tests** (extension host):

```bash
npm test
```

Manual playground: `test-files/vulnerable.js` (comments describe expected behavior).

---

## Development

```bash
npm install
npm run compile    # typecheck + lint + esbuild → dist/extension.js
```

Press **F5** to launch the Extension Development Host.

---

## Roadmap (what’s left)

| Area | Status |
|------|--------|
| Deeper inter-procedural taint | Partial — known gaps on return-value flow |
| More language support | JS/TS only |
| Fix “Apply” for multi-line / multi-statement patterns | Line-level only today |
| Custom rules / YAML rule packs | Not started |
| GitHub Action / CLI without VS Code | SARIF only via workspace command |
| Baseline / suppressions file (`.snitchlint.json`) | Ignore comments only |
| Marketplace publish + docs site | In progress |
| Broader React/Next.js AST rules | `dangerouslySetInnerHTML` is regex-based |

Contributions and testers welcome—see quickstart for where to plug in new rules.

---

## License & publishing

Check `package.json` for publisher and version. Before Marketplace publish: review `.vscodeignore`, icon, and privacy (default mode sends no code externally).

---

## Links

- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [CWE](https://cwe.mitre.org/)
- [Ollama](https://ollama.com/) (optional local AI)
