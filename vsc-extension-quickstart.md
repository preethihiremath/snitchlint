# SnitchLint — Extension development quickstart

This guide explains **how the entire codebase works**, file by file, and how to extend it. Read this after skimming [README.md](./README.md).

---

## 1. End-to-end flow (one scan)

When you open or edit a JS/TS file:

```
User edits file
    → extension.ts: scheduleAnalysis() [debounced]
    → runAnalysis(document)
    → scanDocument() in engine/scanner.ts
         1. createSourceFileForScan() — parse text to TypeScript AST
         2. new TaintAnalyzer(sourceFile) — build taint model once
         3. For each rule in registry: rule.analyze(ctx) → Finding[]
         4. enrichFindings() — attach CWE + taint flow metadata
    → findingsToDiagnostics() — Finding[] → vscode.Diagnostic[]
    → diagnosticCollection.set(uri, diagnostics) — Problems panel
```

When you open **AI Insight**:

```
User: lightbulb / command snitchlint.showAiInsight
    → extension.ts: find Finding at cursor from scanCache
    → AiInsightPanel.show()
         buildExplanation(finding)
         buildFixSuggestion(finding, fileText)
         [optional] enhanceExplanation() via Ollama or vscode.lm
    → Webview HTML with taint flow, CWE, before/after
    → User clicks Apply → WorkspaceEdit replaces line with fix.after
```

---

## 2. File-by-file reference

### Entry & VS Code glue

#### `src/extension.ts`

- **`activate()`** — Registers everything on startup (`onStartupFinished`).
- **`diagnosticCollection`** — Named `snitchlint`; holds per-file diagnostics.
- **`scanCache`** — `Map<uri, { version, findings }>` so AI panel and commands reuse the last scan without re-parsing.
- **`runAnalysis()`** — Filters language → `scanDocument()` → sets diagnostics.
- **`scheduleAnalysis()`** — Debounces `onDidChangeTextDocument` using `snitchlint.debounceMs`.
- **Commands:**
  - `snitchlint.scan` — manual rescan
  - `snitchlint.scanWorkspace` — all `**/*.{ts,tsx,js,jsx}` → `snitchlint.sarif`
  - `snitchlint.showAiInsight` — AI panel at cursor
  - `snitchlint.showAiInsightForDiagnostic` — internal; called from code action with uri/line/ruleId
- **Code actions** — Ignore comment quick fix + “Explain & Suggest Fix”.
- **`applyFixToEditor()`** — Replaces the **full line** containing the finding with `fix.after` when `canApply` is true.

#### `src/adapters/vscodeDiagnostics.ts`

- Converts UTF-16 `Finding.start/end` to `vscode.Range`.
- Maps severity; sets `source: 'SnitchLint'`, `code: ruleId`.
- Filters `// snitchlint-ignore` on same or previous line.
- Adds `relatedInformation` from `finding.suggestion` when present.

#### `src/config/configuration.ts`

- **`SnitchLintConfiguration`** — Pure TypeScript interface (no `vscode` import).
- Used by unit tests via `createTestConfiguration()`.

#### `src/config/vscodeConfiguration.ts`

- Reads `snitchlint.*` from `vscode.workspace.getConfiguration()`.
- Bridges to `SnitchLintConfiguration` including `ai.*` settings.

#### `src/logging/logger.ts`

- Output channel **SnitchLint**; respects `logLevel`.

---

### Engine (VS Code–agnostic)

#### `src/engine/createSourceFile.ts`

- Wraps `typescript.createSourceFile` with consistent script target / module kind for JS and TS.

#### `src/engine/scanner.ts`

- **`scanDocument(input, rules, config, onRuleError)`** — Single entry for analysis.
- Parses once, builds **`RuleContext`**: `{ sourceFile, fullText, taint, isRuleEnabled }`.
- Runs each enabled rule in **try/catch** so one broken rule does not kill the scan.
- Returns **`enrichFindings(findings)`** so every finding has CWE/taint metadata for the AI layer.

#### `src/engine/taintAnalyzer.ts`

- **Purpose:** Answer “is this expression influenced by untrusted input?”
- **Sources:** Strings like `req.body`, `req.query` (see `rules/constants.ts`).
- **Model:** Monotonic fixpoint over function scopes — taint only grows, never shrinks (conservative).
- **Propagation:** Assignments, parameters from tainted call sites, conservative call returns.
- **`getTaintOrigins(expr)`** — Returns `Set<string>` of source labels (e.g. `req.query.id`).
- **Not full dataflow:** Return values and deep property paths have known limitations (`test-files/vulnerable.js` documents gaps).

---

### Rules layer

#### `src/rules/ruleTypes.ts`

- **`SecurityRule`** — `id`, `title`, `owasp`, `description`, `analyze(ctx)`.
- **`RuleContext`** — Shared AST + taint per file.

#### `src/rules/registry.ts`

- **`allSecurityRules`** — Ordered array of 16 rules. **Append new rules here.**

#### `src/rules/constants.ts`

- **`TAINT_SOURCES`** — Substrings that mark untrusted input.
- **`SQL_SINK_METHODS`** — Method names for SQL injection rule.

#### `src/rules/findingHelpers.ts`

- **`buildTaintFinding()`** — Creates a `Finding` with `taintFlow[]` (source → propagation → sink), CWE fields from `ruleMetadata`.

#### `src/rules/*Rule.ts` (one file per rule)

Example — **`sqlInjectionRule.ts`:**

1. Fast-path: skip file if no `TAINT_SOURCES` substring in text.
2. Walk AST for `CallExpression` with sink method name.
3. For each argument, `ctx.taint.getTaintOrigins(arg)`.
4. If tainted → `buildTaintFinding({ origins, sinkApi: methodName, ... })`.

Other rules use taint, regex, or heuristics as appropriate.

#### `src/metadata/ruleMetadata.ts`

- **`RULE_SECURITY_METADATA`** — Per `ruleId`: `vulnerabilityType`, `cweId`, `cweName`, `whyItMatters`, `riskyPatterns`.
- Used by enricher, explanation builder, and AI panel.

---

### AI layer

#### `src/types/findings.ts`

- **`Finding`** — Core model: offsets, message, optional `taintFlow`, `cweId`, `vulnerabilityType`, `riskyApi`.
- **`TaintFlowStep`** — `kind: 'source' | 'propagation' | 'sink'`.

#### `src/ai/findingEnricher.ts`

- Runs after all rules; fills missing CWE/taint from metadata + regex on `finding.message`.

#### `src/ai/explanationBuilder.ts`

- **`buildExplanation(finding)`** → `SecurityExplanation` (summary, why, OWASP short label, taint steps for UI).

#### `src/ai/fixSuggestionBuilder.ts`

- **`buildFixSuggestion(finding, fileText)`** → `{ before, after, rationale, canApply }`.
- **`FIX_HANDLERS`** — Per-rule transforms (e.g. SQL `?` placeholders, `innerHTML` → `textContent`).
- **`canApply: true`** only when a full line can be replaced safely.

#### `src/ai/optionalAiClient.ts`

- **`enhanceExplanation(prompt, options, lmEnhancer?)`** — Optional Ollama HTTP or VS Code LM callback.
- Default path does not call this.

#### `src/ui/aiInsightPanel.ts`

- **`AiInsightPanel.show()`** — Builds payload, optional AI enhance, sets webview HTML.
- CSP-safe inline styles using VS Code theme variables.
- **`postMessage({ type: 'applyFix' })`** → extension applies edit.

---

### Build & manifest

#### `esbuild.js`

- Bundles `src/extension.ts` → `dist/extension.js` (CJS, `vscode` external).

#### `package.json`

- `contributes`: commands, settings, context menu.
- `main`: `./dist/extension.js`.

---

## 3. Adding a new security rule

1. Create `src/rules/myNewRule.ts` implementing `SecurityRule`.
2. Add entry to `RULE_SECURITY_METADATA` in `src/metadata/ruleMetadata.ts`.
3. Register in `src/rules/registry.ts`.
4. Add fixture under `src/test/fixtures/` and assert in `src/test/unit/scanner.test.ts`.
5. If taint-based, use `buildTaintFinding()` and extend `FIX_HANDLERS` in `fixSuggestionBuilder.ts`.

---

## 4. Debugging

| Task | How |
|------|-----|
| Run extension | F5 → Extension Development Host |
| Breakpoints | Set in `src/*.ts`; maps via esbuild `sourcemap` in dev |
| Logs | Output channel **SnitchLint**; set `snitchlint.logLevel` to `debug` |
| Test one rule | `npm run test:unit` with a minimal fixture file |
| AI panel | Open fixture, trigger finding, command **Explain Vulnerability** |

---

## 5. Test layout

| Path | Purpose |
|------|---------|
| `src/test/unit/scanner.test.ts` | Full scan on OWASP fixture |
| `src/test/unit/ai.test.ts` | Explanation, enricher, SQL fix |
| `src/test/integration/extension.test.ts` | Extension loads, commands registered |
| `src/test/fixtures/*.ts` | Vulnerable samples |
| `test-files/vulnerable.js` | Manual taint edge cases (not automated) |

```bash
npm run compile
npm run test:unit
npm test   # downloads VS Code test host if needed
```

---

## 6. Packaging checklist

- [ ] `npm run package` (production esbuild)
- [ ] `vsce package` (if using VSCE CLI)
- [ ] Verify `.vscodeignore` excludes `src/` but includes `dist/`
- [ ] Privacy: document that default mode is offline; Ollama is opt-in
- [ ] CHANGELOG + version bump in `package.json`

---

## 7. Known limitations (for contributors)

- Taint does not fully track returns across all call patterns.
- React XSS rule is regex-based, not AST-taint.
- Apply-fix replaces one line only.
- CSRF / file-upload rules are heuristics, not proof of vulnerability.

Improve these in `taintAnalyzer.ts` or individual rules without changing the `Finding` contract when possible.
