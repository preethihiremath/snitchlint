import * as ts from 'typescript';
import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from './ruleTypes';

/** Sensitive data in logs (A09). */
export const loggingRule: SecurityRule = {
  id: 'sensitive-logging',
  title: 'Sensitive data in logs',
  owasp: 'A09:2021-Security Logging and Monitoring Failures',
  description: 'console.log patterns that may leak passwords/tokens.',
  analyze(ctx: RuleContext): readonly Finding[] {
    const out: Finding[] = [];
    const sf = ctx.sourceFile;

    function walk(node: ts.Node): void {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const obj = node.expression.expression.getText(sf);
        const method = node.expression.name.text;
        if (obj === 'console' && (method === 'log' || method === 'info' || method === 'debug' || method === 'warn')) {
          const joined = node.arguments.map((a) => a.getText(sf)).join(' ');
          if (/password|secret|token|apiKey|authorization/i.test(joined)) {
            const start = node.getStart(sf);
            const end = node.getEnd();
            out.push({
              ruleId: 'sensitive-logging',
              severity: 'information',
              message: 'Logging may include sensitive fields (password/token/secret).',
              suggestion: 'Redact secrets; use structured logging with allowlisted fields.',
              start,
              end,
              owasp: 'A09:2021-Security Logging and Monitoring Failures',
            });
          }
        }
      }
      ts.forEachChild(node, walk);
    }

    walk(sf);
    return out;
  },
};
