import * as ts from 'typescript';
import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from './ruleTypes';

export const csrfRule: SecurityRule = {
  id: 'csrf-protection',
  title: 'CSRF protection',
  owasp: 'A01:2021-Broken Access Control',
  description: 'Heuristic: middleware using body parsers without CSRF middleware.',
  analyze(ctx: RuleContext): readonly Finding[] {
    const diagnostics: Finding[] = [];
    const sourceFile = ctx.sourceFile;

    function walk(node: ts.Node): void {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'use') {
        const args = node.arguments.map((arg) => arg.getText(sourceFile));
        const usesCsrf = args.some((arg) => arg.toLowerCase().includes('csrf'));

        if (!usesCsrf && args.some((arg) => /bodyparser|urlencoded|json/i.test(arg))) {
          const start = node.getStart(sourceFile);
          const end = node.getEnd();
          diagnostics.push({
            ruleId: 'csrf-protection',
            severity: 'information',
            message: 'Body parsing middleware may need CSRF protection for state-changing browser requests.',
            suggestion: 'Use CSRF tokens, SameSite cookies, or framework CSRF modules for cookie-based sessions.',
            start,
            end,
            owasp: 'A01:2021-Broken Access Control',
          });
        }
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return diagnostics;
  },
};
