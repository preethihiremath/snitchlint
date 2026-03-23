import * as ts from 'typescript';
import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from './ruleTypes';

export const openRedirectRule: SecurityRule = {
  id: 'open-redirect',
  title: 'Open redirect',
  owasp: 'A01:2021-Broken Access Control',
  description: 'Redirect targets derived from request parameters.',
  analyze(ctx: RuleContext): readonly Finding[] {
    const diagnostics: Finding[] = [];
    const sourceFile = ctx.sourceFile;

    function walk(node: ts.Node): void {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === 'redirect' &&
        node.arguments.length > 0
      ) {
        const arg = node.arguments[0];
        const argText = arg.getText(sourceFile);
        if (/req\.query|req\.body|req\.params/.test(argText)) {
          const start = arg.getStart(sourceFile);
          const end = arg.getEnd();
          diagnostics.push({
            ruleId: 'open-redirect',
            severity: 'warning',
            message: 'Open redirect risk: redirect URL may be controlled by the client.',
            suggestion: 'Allowlist hosts/paths or use fixed redirect maps.',
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
