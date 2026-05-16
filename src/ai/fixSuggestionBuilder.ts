/**
 * Rule-specific secure code suggestions (before/after).
 * FIX_HANDLERS transform the line around the finding; canApply gates WorkspaceEdit.
 */
import type { Finding } from '../types';

export interface FixSuggestion {
  readonly before: string;
  readonly after: string;
  readonly rationale: string;
  readonly canApply: boolean;
}

export function buildFixSuggestion(finding: Finding, fileText: string): FixSuggestion {
  const snippet = fileText.slice(finding.start, finding.end).trim();
  const lineContext = getLineContext(fileText, finding.start);
  const handler = FIX_HANDLERS[finding.ruleId];
  if (handler) {
    return handler({ finding, snippet, lineContext, fileText });
  }
  return genericFix(finding, snippet, lineContext);
}

interface FixContext {
  readonly finding: Finding;
  readonly snippet: string;
  readonly lineContext: string;
  readonly fileText: string;
}

type FixHandler = (ctx: FixContext) => FixSuggestion;

function getLineContext(text: string, offset: number): string {
  const lineStart = text.lastIndexOf('\n', offset - 1) + 1;
  const lineEnd = text.indexOf('\n', offset);
  return text.slice(lineStart, lineEnd === -1 ? undefined : lineEnd);
}

function genericFix(finding: Finding, snippet: string, lineContext: string): FixSuggestion {
  const before = snippet || lineContext.trim();
  return {
    before,
    after: before,
    rationale:
      finding.suggestion ??
      'Review this code path: validate and encode input, use safe APIs, and apply defense in depth.',
    canApply: false,
  };
}

const FIX_HANDLERS: Record<string, FixHandler> = {
  'sql-injection': (ctx) => {
    const { lineContext, snippet } = ctx;
    const line = lineContext.trim();

    if (/\.query\s*\(\s*`/.test(line) || /\.execute\s*\(\s*`/.test(line)) {
      const paramMatch = snippet.match(/\$\{([^}]+)\}/);
      const param = paramMatch?.[1]?.trim() ?? 'userInput';
      const before = line;
      const after = line
        .replace(/\.query\s*\(\s*`[^`]*`\s*\)/, `.query('SELECT * FROM users WHERE id = ?', [${param}])`)
        .replace(/\.execute\s*\(\s*`[^`]*`\s*\)/, `.execute('SELECT * FROM users WHERE id = ?', [${param}])`);
      if (after !== before) {
        return {
          before,
          after,
          rationale:
            'Use parameterized queries (placeholders) so the database driver treats user input as data, not SQL syntax.',
          canApply: true,
        };
      }
    }

    if (/\.query\s*\(/.test(line) && snippet && !snippet.includes('?')) {
      const before = line;
      const varName = snippet.replace(/[`'"]/g, '').split(/\s/)[0] || 'query';
      const after = line.replace(
        /\.query\s*\(\s*([^,)]+)\s*\)/,
        `.query('SELECT * FROM users WHERE id = ?', [${varName.includes('query') ? 'id' : varName}])`
      );
      return {
        before,
        after,
        rationale: 'Pass SQL with ? placeholders and bind values in a separate array — never build SQL from user strings.',
        canApply: after !== before,
      };
    }

    return {
      before: line || snippet,
      after: `// Use parameterized queries\nconst rows = await db.query('SELECT * FROM users WHERE id = ?', [id]);`,
      rationale:
        'Replace string-built SQL with driver-supported placeholders (?, $1) and bound parameters.',
      canApply: false,
    };
  },

  xss: (ctx) => {
    const line = ctx.lineContext.trim();
    if (/\.innerHTML\s*=/.test(line)) {
      const rhs = line.split('=').slice(1).join('=').trim();
      const before = line;
      const after = line.replace(/\.innerHTML\s*=\s*.+;?$/, `.textContent = ${rhs};`);
      return {
        before,
        after,
        rationale:
          'textContent treats data as plain text. For HTML, sanitize with DOMPurify.sanitize() before assigning to innerHTML.',
        canApply: after !== before,
      };
    }
    if (/document\.write\s*\(/.test(line)) {
      const before = line;
      const after = line.replace(
        /document\.write\s*\(([^)]+)\)/,
        'document.createTextNode($1) /* prefer appendChild; never write raw HTML */'
      );
      return {
        before,
        after,
        rationale: 'Avoid document.write. Use createTextNode or framework-safe rendering with output encoding.',
        canApply: after !== before,
      };
    }
    return genericFix(ctx.finding, ctx.snippet, ctx.lineContext);
  },

  'command-injection': (ctx) => {
    const line = ctx.lineContext.trim();
    const before = line;
    const after = line
      .replace(/\bexec\s*\(/, 'execFile(')
      .replace(/\bexecSync\s*\(/, 'execFileSync(')
      .replace(/child_process\.exec/, 'child_process.execFile');
    return {
      before,
      after: after.includes('execFile')
        ? `${after}\n// execFile: pass command + fixed args array; never pass a shell string built from user input`
        : `import { execFile } from 'node:child_process';\nexecFile('allowed-binary', ['fixed-arg'], callback);`,
      rationale:
        'Use execFile with a fixed executable and argument array. Validate input against an allowlist; never pass user strings to a shell.',
      canApply: after !== before && /exec/.test(line),
    };
  },

  'insecure-deserialization': (ctx) => {
    const line = ctx.lineContext.trim();
    const before = line;
    const after = line.replace(
      /JSON\.parse\s*\(([^)]+)\)/,
      'JSON.parse($1, (key, value) => (key === "__proto__" || key === "constructor" ? undefined : value))'
    );
    return {
      before,
      after: `${after}\n// Also validate shape with zod/io-ts before trusting parsed data`,
      rationale:
        'Block prototype-pollution keys in reviver and validate schema before using parsed objects in security logic.',
      canApply: /JSON\.parse/.test(line),
    };
  },

  ssrf: (ctx) => {
    const line = ctx.lineContext.trim();
    return {
      before: line,
      after: `const allowedHosts = new Set(['api.example.com']);\nconst url = new URL(userUrl);\nif (!allowedHosts.has(url.hostname)) throw new Error('SSRF blocked');\nawait fetch(url.toString());`,
      rationale:
        'Allowlist destination hostnames, block private IP ranges, and disable redirects to internal networks.',
      canApply: false,
    };
  },

  'path-traversal': (ctx) => {
    const line = ctx.lineContext.trim();
    return {
      before: line,
      after: `import path from 'node:path';\nconst safeBase = path.resolve('/var/app/uploads');\nconst resolved = path.resolve(safeBase, userPath);\nif (!resolved.startsWith(safeBase)) throw new Error('Path traversal');\nfs.readFile(resolved, callback);`,
      rationale: 'Resolve paths and ensure the result stays under a trusted base directory.',
      canApply: false,
    };
  },

  'open-redirect': (ctx) => {
    const line = ctx.lineContext.trim();
    return {
      before: line,
      after: line.replace(
        /res\.redirect\s*\([^)]+\)/,
        "res.redirect('/dashboard') /* use fixed paths or allowlisted relative URLs only */"
      ),
      rationale: 'Only redirect to fixed internal paths or URLs validated against an allowlist — never raw query parameters.',
      canApply: /res\.redirect/.test(line),
    };
  },

  'hardcoded-secrets': (ctx) => {
    const line = ctx.lineContext.trim();
    return {
      before: line,
      after: line.replace(/(api[_-]?key|secret|password|token)\s*=\s*['"][^'"]+['"]/i, "$1 = process.env.APP_SECRET"),
      rationale: 'Load secrets from environment variables or a secret manager — never commit them to source control.',
      canApply: /=\s*['"]/.test(line),
    };
  },

  'weak-crypto': (ctx) => {
    const line = ctx.lineContext.trim();
    const after = line
      .replace(/createHash\s*\(\s*['"]md5['"]\s*\)/i, "createHash('sha256')")
      .replace(/createHash\s*\(\s*['"]sha1['"]\s*\)/i, "createHash('sha256')");
    return {
      before: line,
      after: /password|passwd/i.test(ctx.fileText)
        ? `${after}\n// For passwords use bcrypt or argon2, not fast hashes`
        : after,
      rationale: 'Use SHA-256 or stronger for integrity; use bcrypt/argon2 for password storage.',
      canApply: after !== line,
    };
  },

  'insecure-cookie-flags': (ctx) => {
    const line = ctx.lineContext.trim();
    return {
      before: line,
      after: line.replace(
        /res\.cookie\s*\(/,
        'res.cookie(/* name */, /* value */, { httpOnly: true, secure: true, sameSite: "strict" }'
      ),
      rationale: 'Set httpOnly (no JS access), secure (HTTPS only), and sameSite to reduce theft via XSS and CSRF.',
      canApply: /res\.cookie/.test(line),
    };
  },

  'jwt-weak-secret': (ctx) => {
    const line = ctx.lineContext.trim();
    return {
      before: line,
      after: line.replace(/jwt\.sign\s*\([^,]+,\s*['"][^'"]+['"]/, 'jwt.sign(payload, process.env.JWT_SECRET'),
      rationale: 'Use a long random secret from environment (≥256 bits). Prefer asymmetric RS256 for multi-service setups.',
      canApply: /jwt\.sign/.test(line) && /['"]/.test(line),
    };
  },

  'react-dangerously-set-inner-html': (ctx) => {
    const line = ctx.lineContext.trim();
    return {
      before: line,
      after: line.replace(
        /dangerouslySetInnerHTML\s*=\s*\{\s*__html:\s*([^}]+)\s*\}/,
        '{children: DOMPurify.sanitize($1) } /* or render escaped text */'
      ),
      rationale: 'Sanitize HTML with DOMPurify before rendering, or avoid raw HTML entirely.',
      canApply: /dangerouslySetInnerHTML/.test(line),
    };
  },

  'insecure-eval-function': (ctx) => {
    const line = ctx.lineContext.trim();
    return {
      before: line,
      after: line.replace(/\beval\s*\(/, '/* removed eval — parse JSON or use a safe DSL */ JSON.parse('),
      rationale: 'Never evaluate user strings as code. Use JSON.parse, schema validation, or a restricted expression language.',
      canApply: false,
    };
  },

  'sensitive-logging': (ctx) => {
    const line = ctx.lineContext.trim();
    return {
      before: line,
      after: line.replace(/(password|token|secret|apiKey)/gi, '***REDACTED***'),
      rationale: 'Redact sensitive fields before logging. Log event types and non-sensitive identifiers only.',
      canApply: /(password|token|secret)/i.test(line),
    };
  },
};
