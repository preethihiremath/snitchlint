import * as ts from 'typescript';
import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from './ruleTypes';

export const deserializationRule: SecurityRule = {
  id: 'insecure-deserialization',
  title: 'Insecure deserialization',
  owasp: 'A08:2021-Software and Data Integrity Failures',
  description: 'Flags JSON.parse on request-like input (prototype pollution / logic risks).',
  analyze(ctx: RuleContext): readonly Finding[] {
    const diagnostics: Finding[] = [];
    const sourceFile = ctx.sourceFile;

    function walk(node: ts.Node): void {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.expression.getText(sourceFile) === 'JSON' &&
        node.expression.name.getText(sourceFile) === 'parse'
      ) {
        const arg0 = node.arguments[0];
        if (arg0) {
          const origins = ctx.taint.getTaintOrigins(arg0);
          if (origins.size > 0) {
          const start = node.getStart(sourceFile);
          const end = node.getEnd();
          diagnostics.push({
            ruleId: 'insecure-deserialization',
            severity: 'warning',
            message: 'JSON.parse on untrusted input can enable prototype pollution or unsafe object graphs.',
            suggestion: 'Validate schema; use Object.create(null) or safe parsers; avoid merging into shared prototypes.',
            start,
            end,
            owasp: 'A08:2021-Software and Data Integrity Failures',
          });
          }
        }
      }

      ts.forEachChild(node, walk);
    }

    if (!ctx.fullText || !/req\.|request\.|params|query|body|input|user/i.test(ctx.fullText)) return [];
    walk(sourceFile);
    return diagnostics;
  },
};
