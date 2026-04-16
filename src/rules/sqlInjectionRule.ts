import * as ts from 'typescript';
import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from './ruleTypes';
import { TAINT_SOURCES, SQL_SINK_METHODS } from './constants';

export const sqlInjectionRule: SecurityRule = {
  id: 'sql-injection',
  title: 'SQL injection',
  owasp: 'A03:2021-Injection',
  description: 'Detects tainted data flowing into common SQL driver methods.',
  analyze(ctx: RuleContext): readonly Finding[] {
    const diagnostics: Finding[] = [];
    const sf = ctx.sourceFile;

    const walk = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const methodName = node.expression.name.text;
        if ((SQL_SINK_METHODS as readonly string[]).includes(methodName)) {
          node.arguments.forEach((arg, index) => {
            const origins = ctx.taint.getTaintOrigins(arg);
            if (origins.size === 0) return;
            const origin = origins.values().next().value as string;
            const start = arg.getStart(sf);
            const end = arg.getEnd();
            diagnostics.push({
              ruleId: 'sql-injection',
              severity: 'warning',
              message: `Potential SQL injection: tainted data from "${origin}" reaches SQL method "${methodName}" (argument ${index + 1}).`,
              suggestion: 'Use parameterized queries / prepared statements; never concatenate user input into SQL.',
              start,
              end,
              owasp: 'A03:2021-Injection',
            });
          });
        }
      }
      ts.forEachChild(node, walk);
    };

    // A quick fast-path: if the file never mentions known taint sources, skip the walk.
    const text = ctx.fullText;
    if (!TAINT_SOURCES.some((s) => text.includes(s))) return [];

    walk(sf);
    return diagnostics;
  },
};
