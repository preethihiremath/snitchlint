import * as ts from 'typescript';
import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from './ruleTypes';

export const cookieFlagsRule: SecurityRule = {
  id: 'insecure-cookie-flags',
  title: 'Insecure cookie flags',
  owasp: 'A05:2021-Security Misconfiguration',
  description: 'Cookie setters missing Secure and/or HttpOnly.',
  analyze(ctx: RuleContext): readonly Finding[] {
    const diagnostics: Finding[] = [];
    const sourceFile = ctx.sourceFile;

    function cookieOptionsArg(call: ts.CallExpression): ts.ObjectLiteralExpression | undefined {
      const args = call.arguments;
      if (args.length >= 3 && ts.isObjectLiteralExpression(args[2])) {
        return args[2];
      }
      if (args.length >= 2 && ts.isObjectLiteralExpression(args[1])) {
        return args[1];
      }
      return undefined;
    }

    function walk(node: ts.Node): void {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'cookie') {
        const optionsLiteral = cookieOptionsArg(node);
        if (optionsLiteral) {
          const flags = optionsLiteral.properties.map((p) =>
            ts.isPropertyAssignment(p) && ts.isIdentifier(p.name) ? p.name.text : ''
          );
          const hasSecure = flags.includes('secure');
          const hasHttpOnly = flags.includes('httpOnly');

          if (!hasSecure || !hasHttpOnly) {
            const start = node.getStart(sourceFile);
            const end = node.getEnd();
            const missing =
              !hasSecure && !hasHttpOnly ? 'Secure and HttpOnly' : !hasSecure ? 'Secure' : 'HttpOnly';
            diagnostics.push({
              ruleId: 'insecure-cookie-flags',
              severity: 'warning',
              message: `Session cookie may be missing ${missing} flags.`,
              suggestion: 'Set secure, httpOnly, and sameSite appropriately for your deployment.',
              start,
              end,
              owasp: 'A05:2021-Security Misconfiguration',
            });
          }
        }
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return diagnostics;
  },
};
