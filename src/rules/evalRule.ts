import * as ts from 'typescript';
import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from './ruleTypes';

export const evalRule: SecurityRule = {
  id: 'insecure-eval-function',
  title: 'Insecure eval / Function',
  owasp: 'A03:2021-Injection',
  description: 'Flags eval() and new Function() with dynamic input.',
  analyze(ctx: RuleContext): readonly Finding[] {
    const diagnostics: Finding[] = [];
    const sourceFile = ctx.sourceFile;

    function walk(node: ts.Node): void {
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'eval') {
        const argText = node.arguments[0]?.getText(sourceFile) || '';
        if (/req|input|param|user/i.test(argText)) {
          const start = node.getStart(sourceFile);
          const end = node.getEnd();
          diagnostics.push({
            ruleId: 'insecure-eval-function',
            severity: 'error',
            message: 'eval() with dynamic or untrusted input is unsafe.',
            suggestion: 'Remove eval; use JSON.parse for data, or a safe expression evaluator if truly required.',
            start,
            end,
            owasp: 'A03:2021-Injection',
          });
        }
      }

      if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'Function') {
        const argsText = node.arguments?.map((arg) => arg.getText(sourceFile)).join(', ') || '';
        if (/req|input|param|user/i.test(argsText)) {
          const start = node.getStart(sourceFile);
          const end = node.getEnd();
          diagnostics.push({
            ruleId: 'insecure-eval-function',
            severity: 'error',
            message: 'new Function() with dynamic input can execute arbitrary code.',
            suggestion: 'Avoid constructing functions from user-controlled strings.',
            start,
            end,
            owasp: 'A03:2021-Injection',
          });
        }
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return diagnostics;
  },
};
