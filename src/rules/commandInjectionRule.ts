import * as ts from 'typescript';
import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from './ruleTypes';

const SHELL_EXEC_FUNCTIONS = ['exec', 'execSync', 'spawn', 'spawnSync'] as const;

export const commandInjectionRule: SecurityRule = {
  id: 'command-injection',
  title: 'Command injection',
  owasp: 'A03:2021-Injection',
  description: 'Detects child_process calls with user-influenced arguments.',
  analyze(ctx: RuleContext): readonly Finding[] {
    const diagnostics: Finding[] = [];
    const sourceFile = ctx.sourceFile;

    function reportIfUserControlled(functionName: string, node: ts.CallExpression): void {
      const argText = node.arguments[0]?.getText(sourceFile) || '';
      if (!/req|input|user|params/i.test(argText)) {
        return;
      }
      const start = node.getStart(sourceFile);
      const end = node.getEnd();
      diagnostics.push({
        ruleId: 'command-injection',
        severity: 'error',
        message: `Possible command injection: ${functionName} may receive untrusted input.`,
        suggestion: 'Avoid shell execution on user data; use allowlists, fixed arguments, or safer APIs.',
        start,
        end,
        owasp: 'A03:2021-Injection',
      });
    }

    function walk(node: ts.Node): void {
      if (ts.isCallExpression(node)) {
        if (ts.isPropertyAccessExpression(node.expression)) {
          const { name, expression } = node.expression;
          const functionName = name.getText(sourceFile);
          const moduleName = expression.getText(sourceFile);

          if (
            (moduleName.includes('child_process') || moduleName === 'cp') &&
            SHELL_EXEC_FUNCTIONS.includes(functionName as (typeof SHELL_EXEC_FUNCTIONS)[number])
          ) {
            reportIfUserControlled(functionName, node);
          }
        } else if (ts.isIdentifier(node.expression)) {
          const fn = node.expression.text;
          if (SHELL_EXEC_FUNCTIONS.includes(fn as (typeof SHELL_EXEC_FUNCTIONS)[number])) {
            reportIfUserControlled(fn, node);
          }
        }
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return diagnostics;
  },
};
