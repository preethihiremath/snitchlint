# Change Log

All notable changes to the "snitchlint" extension will be documented in this file.

Check [Keep a Changelog](http://keepachangelog.com/) for recommendations on how to structure this file.

## [0.2.0] - 2026-05-16

## Added

- **AI Insight panel**: vulnerability explanation, taint flow (source → propagation → sink), OWASP + CWE mapping, risky API/patterns.
- **AI fix suggestions**: rule-specific before/after code with optional **Apply fix** in the editor.
- CWE and vulnerability-type metadata for all 16 rules (`src/metadata/ruleMetadata.ts`).
- Structured taint findings via `buildTaintFinding()` for SQLi, XSS, and command injection rules.
- Optional enhancement: **Ollama** (local, free) and **VS Code Language Model API** settings under `snitchlint.ai.*`.
- Commands: `SnitchLint: Explain Vulnerability & Suggest Fix`, code action on diagnostics, editor context menu.
- Unit tests for explanation, enricher, and fix builders.

## Changed

- `Finding` type extended with `taintFlow`, `cweId`, `cweName`, `vulnerabilityType`, `riskyApi`.
- Scanner post-processes findings through `enrichFindings()`.

## [0.1.0] - 2026-03-22

## Added

- Production-ready VS Code extension structure: shared engine, rules layer, config, logging, and VS Code diagnostics adapter.
- User configuration via `snitchlint.*` settings (enable/disable, debounce, log level, per-rule toggles).
- OWASP-oriented rule expansion and metadata (new/expanded heuristics: SSRF, path traversal, React `dangerouslySetInnerHTML`, sensitive logging, JWT weak/hardcoded secret).
- Unit + integration test coverage, including an OWASP Top 10 sample fixture.

## Changed

- Refactored scanning pipeline to parse the document once per scan and run rules with per-rule isolation.
- Improved diagnostics: stable `code`, severity mapping, and optional remediation suggestions.

## Fixed

- Removed invalid self-dependency and cleaned up old analyzer/runner code paths after the refactor.
- Improved detection coverage for common import patterns (e.g., `exec`/`spawn` and `crypto.createHash`).

## [0.0.2] - 2025-08-07 

## Added

  - XSS detection
  - Secrets detection 
  - Command Injection
  - Insecure `eval()` / `Function()` Usage
  - Insecure Deserialization
  - Weak Cryptography
  - Unrestricted File Upload
  - Insecure Cookie Flags
  - Lack of CSRF Protection
  - Open Redirect

## Changed 
   - Dynamically picking the detector from the registry 
   
## [0.0.1] -2025-05-25

## Added

- SQL Injection Detector with AST-based Analysis Taint Tracking Taint Propagation SQL Sink Detection


