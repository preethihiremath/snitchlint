import * as ts from 'typescript';
import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from './ruleTypes';
import { TAINT_SOURCES } from './constants';

export const xssRule: SecurityRule = {
  id: 'xss',
  title: 'Cross-site scripting (DOM)',
  owasp: 'A03:2021-Injection',
  description: 'Flags innerHTML and document.write with user-influenced data.',
  analyze(ctx: RuleContext): readonly Finding[] {
    const diagnostics: Finding[] = [];
    const sourceFile = ctx.sourceFile;
    const taintMap = new Map<string, boolean>();

    function collectTaints(node: ts.Node): void {
      if (ts.isVariableDeclaration(node) && node.initializer && ts.isPropertyAccessExpression(node.initializer)) {
        const initText = node.initializer.getText(sourceFile);
        if (TAINT_SOURCES.some((src) => initText.includes(src))) {
          taintMap.set(node.name.getText(sourceFile), true);
        }
      }
      ts.forEachChild(node, collectTaints);
    }

    function checkXSS(node: ts.Node): void {
      if (
        ts.isBinaryExpression(node) &&
        ts.isPropertyAccessExpression(node.left) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        node.left.name.text === 'innerHTML'
      ) {
        const rhs = node.right;
        const rhsText = rhs.getText(sourceFile);
        const isTainted =
          TAINT_SOURCES.some((src) => rhsText.includes(src)) || (ts.isIdentifier(rhs) && taintMap.has(rhs.text));

        if (isTainted) {
          const start = rhs.getStart(sourceFile);
          const end = rhs.getEnd();
          diagnostics.push({
            ruleId: 'xss',
            severity: 'warning',
            message: 'Potential XSS: assigning untrusted data to innerHTML.',
            suggestion: 'Use textContent, sanitize HTML with a trusted library, or framework-safe bindings.',
            start,
            end,
            owasp: 'A03:2021-Injection',
          });
        }
      }

      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === 'write'
      ) {
        const arg = node.arguments[0];
        if (arg) {
          const argText = arg.getText(sourceFile);
          const isTainted =
            TAINT_SOURCES.some((src) => argText.includes(src)) || (ts.isIdentifier(arg) && taintMap.has(arg.text));

          if (isTainted) {
            const start = arg.getStart(sourceFile);
            const end = arg.getEnd();
            diagnostics.push({
              ruleId: 'xss',
              severity: 'warning',
              message: 'Potential XSS: document.write with user-influenced content.',
              suggestion: 'Avoid document.write; use safe DOM APIs and sanitization.',
              start,
              end,
              owasp: 'A03:2021-Injection',
            });
          }
        }
      }

      ts.forEachChild(node, checkXSS);
    }

    collectTaints(sourceFile);
    checkXSS(sourceFile);
    return diagnostics;
  },
};
