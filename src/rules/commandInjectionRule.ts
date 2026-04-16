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
            node.arguments.forEach((arg, index) => {
              const origins = ctx.taint.getTaintOrigins(arg);
              if (origins.size === 0) return;
              const origin = origins.values().next().value as string;
              const start = arg.getStart(sourceFile);
              const end = arg.getEnd();
              diagnostics.push({
                ruleId: 'command-injection',
                severity: 'error',
                message: `Possible command injection: ${functionName} argument ${index + 1} is influenced by "${origin}".`,
                suggestion: 'Avoid shell execution on user data; use allowlists, fixed arguments, or safer APIs.',
                start,
                end,
                owasp: 'A03:2021-Injection',
              });
            });
          }
        } else if (ts.isIdentifier(node.expression)) {
          const fn = node.expression.text;
          if (SHELL_EXEC_FUNCTIONS.includes(fn as (typeof SHELL_EXEC_FUNCTIONS)[number])) {
            node.arguments.forEach((arg, index) => {
              const origins = ctx.taint.getTaintOrigins(arg);
              if (origins.size === 0) return;
              const origin = origins.values().next().value as string;
              const start = arg.getStart(sourceFile);
              const end = arg.getEnd();
              diagnostics.push({
                ruleId: 'command-injection',
                severity: 'error',
                message: `Possible command injection: ${fn} argument ${index + 1} is influenced by "${origin}".`,
                suggestion: 'Avoid shell execution on user data; use allowlists, fixed arguments, or safer APIs.',
                start,
                end,
                owasp: 'A03:2021-Injection',
              });
            });
          }
        }
      }

      ts.forEachChild(node, walk);
    }

    if (!ctx.fullText || !/req\.|request\.|params|query|body|input|user/i.test(ctx.fullText)) {
      return diagnostics;
    }

    walk(sourceFile);
    return diagnostics;
  },
};
