import * as ts from 'typescript';
import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from './ruleTypes';

const WEAK_HASHES = ['md5', 'sha1'] as const;

export const weakCryptoRule: SecurityRule = {
  id: 'weak-crypto',
  title: 'Weak cryptography',
  owasp: 'A02:2021-Cryptographic Failures',
  description: 'Detects deprecated hash algorithms in crypto APIs.',
  analyze(ctx: RuleContext): readonly Finding[] {
    const diagnostics: Finding[] = [];
    const sourceFile = ctx.sourceFile;

    function isCreateHashCall(expr: ts.Expression): boolean {
      if (ts.isPropertyAccessExpression(expr)) {
        const n = expr.name.text;
        return n === 'createHash' || n === 'createHmac';
      }
      if (ts.isIdentifier(expr)) {
        return expr.text === 'createHash' || expr.text === 'createHmac';
      }
      return false;
    }

    function walk(node: ts.Node): void {
      if (ts.isCallExpression(node) && isCreateHashCall(node.expression)) {
        const firstArg = node.arguments[0];
        if (firstArg && ts.isStringLiteral(firstArg) && WEAK_HASHES.includes(firstArg.text.toLowerCase() as (typeof WEAK_HASHES)[number])) {
          const start = node.getStart(sourceFile);
          const end = node.getEnd();
          diagnostics.push({
            ruleId: 'weak-crypto',
            severity: 'warning',
            message: `Weak hash algorithm "${firstArg.text}" is not suitable for security-sensitive use.`,
            suggestion: 'Use SHA-256+ for hashing; for passwords use Argon2/bcrypt/scrypt with proper parameters.',
            start,
            end,
            owasp: 'A02:2021-Cryptographic Failures',
          });
        }
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return diagnostics;
  },
};
