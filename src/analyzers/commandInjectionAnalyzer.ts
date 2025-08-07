import * as ts from 'typescript';
import * as vscode from 'vscode';
import { Analyzer } from '../core/analyzerTypes';

const SHELL_EXEC_FUNCTIONS = ['exec', 'execSync', 'spawn', 'spawnSync'];

export const commandInjectionAnalyzer: Analyzer = {
  id: 'command-injection',
  run: (doc) => {
    const diagnostics: vscode.Diagnostic[] = [];
    const sourceFile = ts.createSourceFile(doc.fileName, doc.getText(), ts.ScriptTarget.Latest, true);

    function checkCommandInjection(node: ts.Node) {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression)
      ) {
        const { name, expression } = node.expression;
        const functionName = name.getText();
        const moduleName = expression.getText();

        if (
          (moduleName.includes('child_process') || moduleName === 'cp') &&
          SHELL_EXEC_FUNCTIONS.includes(functionName)
        ) {
          const argText = node.arguments[0]?.getText() || '';
          if (/req|input|user|params/i.test(argText)) {
            const start = doc.positionAt(node.getStart());
            const end = doc.positionAt(node.getEnd());

            diagnostics.push(new vscode.Diagnostic(
              new vscode.Range(start, end),
              `💥 [SnitchLint-CMD] Possible command injection via "${functionName}(${argText})"`,
              vscode.DiagnosticSeverity.Error
            ));
          }
        }
      }

      ts.forEachChild(node, checkCommandInjection);
    }

    checkCommandInjection(sourceFile);
    return diagnostics;
  }
};
