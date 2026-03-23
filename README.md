# SnitchLint

SnitchLint is a VS Code extension that performs static security analysis for JavaScript and TypeScript code and reports findings as diagnostics in the *Problems* panel.

## What it checks

SnitchLint includes rule-based detectors with OWASP Top 10 (2021) mapping. Current coverage includes:

- SQL injection (tainted inputs into common SQL sink methods)
- XSS (DOM sinks like `innerHTML` / `document.write`, plus React `dangerouslySetInnerHTML`)
- Hardcoded secrets (likely API keys/tokens in string literals)
- Command injection (`exec`/`spawn` style APIs with untrusted arguments)
- Insecure `eval()` / `new Function()`
- Insecure deserialization (`JSON.parse` on request-like input)
- Weak cryptography (`md5` / `sha1`)
- Unrestricted file upload heuristic (`multer.single(...)`)
- Insecure cookie flags (`res.cookie(...)` missing `secure` and/or `httpOnly`)
- CSRF protection heuristic (middleware missing CSRF hints)
- Open redirect heuristic (`res.redirect(...)` with request-derived targets)
- Additional heuristics: SSRF (`fetch`-like calls with request-derived URLs), path traversal (`fs` reads with user-influenced paths), sensitive logging, and JWT weak secret (hardcoded string passed to `jwt.sign`)

## Supported languages

- JavaScript
- TypeScript

## Configuration

Settings are under `snitchlint.*`:

- `snitchlint.enabled` (boolean, default `true`): enable/disable SnitchLint
- `snitchlint.debounceMs` (number, default `400`, min `50`): debounce delay after edits
- `snitchlint.logLevel` (`off` | `error` | `warn` | `info` | `debug`, default `warn`): verbosity for the SnitchLint output channel
- `snitchlint.rules` (object): per-rule disable toggles. Set a rule id to `false` to disable it.

Example:

```json
{
  "snitchlint.rules": {
    "sql-injection": false,
    "xss": false
  }
}
```

## Usage

1. Install and enable the extension.
2. Open a JavaScript/TypeScript file. SnitchLint runs automatically on open/change.
3. View results in the *Problems* panel.
4. Run on demand: `Command Palette` -> `SnitchLint: Scan Active File`.

## Testing

Unit tests (rules + engine; no VS Code UI):

```bash
npm run test:unit
```

Integration tests (VS Code test runner; may download VS Code):

```bash
npm test
```

## Development

```bash
npm install
npm run compile
```

Run the extension development host:

- Press `F5` in VS Code.

