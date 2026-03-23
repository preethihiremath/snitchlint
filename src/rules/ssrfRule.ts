import * as ts from 'typescript';
import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from './ruleTypes';

function isUserInfluencedUrl(text: string): boolean {
  return /req\.(query|body|params|url)|request\.(query|body|params|url)|params\.|query\.|body\./i.test(text);
}

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
          const t = urlArg.getText(sf);
          if (isUserInfluencedUrl(t)) {
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

    walk(sf);
    return out;
  },
};
