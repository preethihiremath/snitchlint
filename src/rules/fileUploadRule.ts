import * as ts from 'typescript';
import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from './ruleTypes';

export const fileUploadRule: SecurityRule = {
  id: 'unrestricted-file-upload',
  title: 'Unrestricted file upload',
  owasp: 'A04:2021-Insecure Design',
  description: 'Heuristic for multer-style upload handlers without visible validation.',
  analyze(ctx: RuleContext): readonly Finding[] {
    const diagnostics: Finding[] = [];
    const sourceFile = ctx.sourceFile;

    function walk(node: ts.Node): void {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === 'single' &&
        node.arguments.length > 0
      ) {
        const start = node.getStart(sourceFile);
        const end = node.getEnd();
        diagnostics.push({
          ruleId: 'unrestricted-file-upload',
          severity: 'warning',
          message: 'File upload handler detected: ensure content type, size limits, extension allowlists, and virus scanning as appropriate.',
          suggestion: 'Validate MIME/type, store outside web root, randomize filenames.',
          start,
          end,
          owasp: 'A04:2021-Insecure Design',
        });
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return diagnostics;
  },
};
