import * as ts from 'typescript';
import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from './ruleTypes';
import { TAINT_SOURCES } from './constants';
import { buildTaintFinding } from './findingHelpers';

export const xssRule: SecurityRule = {
  id: 'xss',
  title: 'Cross-site scripting (DOM)',
  owasp: 'A03:2021-Injection',
  description: 'Flags innerHTML and document.write with user-influenced data.',
  analyze(ctx: RuleContext): readonly Finding[] {
    const diagnostics: Finding[] = [];
    const sourceFile = ctx.sourceFile;

    function checkXSS(node: ts.Node): void {
      if (
        ts.isBinaryExpression(node) &&
        ts.isPropertyAccessExpression(node.left) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        node.left.name.text === 'innerHTML'
      ) {
        const rhs = node.right;
        const origins = ctx.taint.getTaintOrigins(rhs);
        if (origins.size > 0) {
          const start = rhs.getStart(sourceFile);
          const end = rhs.getEnd();
          diagnostics.push(
            buildTaintFinding({
              ruleId: 'xss',
              severity: 'warning',
              message: 'Potential XSS: assigning untrusted data to innerHTML.',
              suggestion: 'Use textContent, sanitize HTML with a trusted library, or framework-safe bindings.',
              start,
              end,
              owasp: 'A03:2021-Injection',
              origins,
              sinkApi: 'element.innerHTML',
              sinkCode: node.getText(sourceFile),
            })
          );
        }
      }

      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === 'write'
      ) {
        const arg = node.arguments[0];
        if (arg) {
          const origins = ctx.taint.getTaintOrigins(arg);
          if (origins.size > 0) {
            const start = arg.getStart(sourceFile);
            const end = arg.getEnd();
            diagnostics.push(
              buildTaintFinding({
                ruleId: 'xss',
                severity: 'warning',
                message: 'Potential XSS: document.write with user-influenced content.',
                suggestion: 'Avoid document.write; use safe DOM APIs and sanitization.',
                start,
                end,
                owasp: 'A03:2021-Injection',
                origins,
                sinkApi: 'document.write',
                sinkCode: node.getText(sourceFile),
              })
            );
          }
        }
      }

      ts.forEachChild(node, checkXSS);
    }

    // Fast-path: if the file never mentions known taint sources, skip scanning for sinks.
    if (!TAINT_SOURCES.some((s) => ctx.fullText.includes(s))) return [];
    checkXSS(sourceFile);
    return diagnostics;
  },
};
