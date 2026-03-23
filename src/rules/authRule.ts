import * as ts from 'typescript';
import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from './ruleTypes';

/**
 * Heuristic for weak JWT signing (hardcoded secret string in jwt.sign).
 */
export const authRule: SecurityRule = {
  id: 'jwt-weak-secret',
  title: 'JWT weak / hardcoded secret',
  owasp: 'A07:2021-Identification and Authentication Failures',
  description: 'jwt.sign with a string literal secret.',
  analyze(ctx: RuleContext): readonly Finding[] {
    const out: Finding[] = [];
    const sf = ctx.sourceFile;

    function walk(node: ts.Node): void {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === 'sign' &&
        node.arguments.length >= 2
      ) {
        const calleeObj = node.expression.expression;
        const calleeName = ts.isIdentifier(calleeObj) ? calleeObj.text : '';
        if (calleeName !== 'jwt' && calleeName !== 'jsonwebtoken') {
          ts.forEachChild(node, walk);
          return;
        }
        const secretArg = node.arguments[1];
        if (secretArg && ts.isStringLiteral(secretArg)) {
          const start = secretArg.getStart(sf);
          const end = secretArg.getEnd();
          out.push({
            ruleId: 'jwt-weak-secret',
            severity: 'warning',
            message: 'JWT signed with a hardcoded string secret in source.',
            suggestion: 'Load signing keys from a KMS/HSM or environment; rotate keys; use strong random material.',
            start,
            end,
            owasp: 'A07:2021-Identification and Authentication Failures',
          });
        }
      }
      ts.forEachChild(node, walk);
    }

    walk(sf);
    return out;
  },
};
