# Extension Quickstart

## Run locally

1. Press `F5` in VS Code to open an Extension Development Host window.
2. Open a JavaScript/TypeScript file. SnitchLint runs automatically and reports findings in the *Problems* panel.
3. To scan the current file on demand: `Command Palette` -> `SnitchLint: Scan Active File`.

## Test

Unit tests (engine + rules; no VS Code UI):

```bash
npm run test:unit
```

Integration tests (VS Code test runner; may download VS Code):

```bash
npm test
```
