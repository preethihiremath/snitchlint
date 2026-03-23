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


## PS: if you want to contribute, reach out to me preethivhiremathvh@gmail.com