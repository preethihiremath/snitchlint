import * as ts from 'typescript';
import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from './ruleTypes';

const FS_READ_NAMES = ['readFile', 'readFileSync', 'createReadStream', 'open', 'openSync', 'readdir', 'readdirSync'] as const;

export const pathTraversalRule: SecurityRule = {
  id: 'path-traversal',
  title: 'Path traversal',
  owasp: 'A01:2021-Broken Access Control',
  description: 'Filesystem APIs with user-influenced paths.',
  analyze(ctx: RuleContext): readonly Finding[] {
    const out: Finding[] = [];
    const sf = ctx.sourceFile;

    function walk(node: ts.Node): void {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const method = node.expression.name.text;
        if (FS_READ_NAMES.includes(method as (typeof FS_READ_NAMES)[number])) {
          const arg0 = node.arguments[0];
          if (arg0) {
            const origins = ctx.taint.getTaintOrigins(arg0);
            if (origins.size > 0) {
              const start = arg0.getStart(sf);
              const end = arg0.getEnd();
              out.push({
                ruleId: 'path-traversal',
                severity: 'warning',
                message: 'Filesystem path may be influenced by untrusted input (path traversal risk).',
                suggestion: 'Canonicalize paths, enforce a chroot/base directory, and reject ".." segments.',
                start,
                end,
                owasp: 'A01:2021-Broken Access Control',
              });
            }
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
