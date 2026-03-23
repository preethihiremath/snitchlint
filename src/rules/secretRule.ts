import * as ts from 'typescript';
import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from './ruleTypes';

const SECRET_PATTERNS: ReadonlyArray<{ name: string; pattern: RegExp }> = [
  { name: 'Stripe live key', pattern: /sk_live_[a-zA-Z0-9]{16,}/ },
  { name: 'Stripe test key', pattern: /sk_test_[a-zA-Z0-9]{16,}/ },
  { name: 'JWT-like', pattern: /eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+/ },
];

/** Long hex/base64-like strings — high false-positive risk; optional via separate id if needed. */
const GENERIC_LONG_SECRET = /[a-fA-F0-9]{32,}|[a-zA-Z0-9+/]{40,}={0,2}/;

export const secretRule: SecurityRule = {
  id: 'hardcoded-secrets',
  title: 'Hardcoded secrets',
  owasp: 'A02:2021-Cryptographic Failures',
  description: 'Detects likely API keys and tokens in string literals.',
  analyze(ctx: RuleContext): readonly Finding[] {
    const diagnostics: Finding[] = [];
    const sourceFile = ctx.sourceFile;

    function checkSecrets(node: ts.Node): void {
      if (ts.isVariableDeclaration(node) && node.initializer && ts.isStringLiteral(node.initializer)) {
        const varName = node.name.getText(sourceFile);
        const value = node.initializer.getText(sourceFile);
        const combined = `${varName} = ${value}`;

        for (const { name, pattern } of SECRET_PATTERNS) {
          if (pattern.test(combined)) {
            const start = node.initializer.getStart(sourceFile);
            const end = node.initializer.getEnd();
            diagnostics.push({
              ruleId: 'hardcoded-secrets',
              severity: 'warning',
              message: `Possible hardcoded secret (${name}). Remove from source and load from a secret manager or environment at runtime.`,
              suggestion: 'Use environment variables, a vault, or CI-injected secrets — never commit real credentials.',
              start,
              end,
              owasp: 'A02:2021-Cryptographic Failures',
            });
            return;
          }
        }

        if (GENERIC_LONG_SECRET.test(value) && /key|secret|token|password/i.test(varName)) {
          const start = node.initializer.getStart(sourceFile);
          const end = node.initializer.getEnd();
          diagnostics.push({
            ruleId: 'hardcoded-secrets',
            severity: 'information',
            message: `Variable name suggests a secret; verify this is not a real credential in source.`,
            suggestion: 'Confirm no real secrets in repo; prefer env-based configuration.',
            start,
            end,
            owasp: 'A02:2021-Cryptographic Failures',
          });
        }
      }

      ts.forEachChild(node, checkSecrets);
    }

    checkSecrets(sourceFile);
    return diagnostics;
  },
};
