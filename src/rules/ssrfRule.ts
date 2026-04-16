import * as ts from 'typescript';
import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from './ruleTypes';

export const ssrfRule: SecurityRule = {
  id: 'ssrf',
  title: 'Server-side request forgery (SSRF)',
  owasp: 'A10:2021-Server-Side Request Forgery',
  description: 'HTTP client calls with URLs built from request data.',
  analyze(ctx: RuleContext): readonly Finding[] {
    const out: Finding[] = [];
    const sf = ctx.sourceFile;

    function walk(node: ts.Node): void {
      if (ts.isCallExpression(node)) {
        let calleeText = '';
        if (ts.isIdentifier(node.expression)) {
          calleeText = node.expression.text;
        } else if (ts.isPropertyAccessExpression(node.expression)) {
          calleeText = node.expression.name.text;
        }

        const isFetchLike = calleeText === 'fetch' || calleeText === 'get' || calleeText === 'request';
        if (isFetchLike && node.arguments.length > 0) {
          const urlArg = node.arguments[0];
          const origins = ctx.taint.getTaintOrigins(urlArg);
          if (origins.size > 0) {
            const start = urlArg.getStart(sf);
            const end = urlArg.getEnd();
            out.push({
              ruleId: 'ssrf',
              severity: 'warning',
              message: 'SSRF risk: URL may be derived from user-controlled request data.',
              suggestion: 'Allowlist hosts/schemes; block internal IPs/metadata endpoints; use a dedicated egress proxy.',
              start,
              end,
              owasp: 'A10:2021-Server-Side Request Forgery',
            });
          }
        }
      }
      ts.forEachChild(node, walk);
    }

    if (!ctx.fullText || !/req\.|request\.|params|query|body|input|user/i.test(ctx.fullText)) return [];
    walk(sf);
    return out;
  },
};
