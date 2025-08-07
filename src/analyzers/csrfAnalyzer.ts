import * as ts from 'typescript';
import * as vscode from 'vscode';
import { Analyzer } from '../core/analyzerTypes';

export const csrfAnalyzer: Analyzer = {
  id: 'csrf-protection',
  run: (doc) => {
    const diagnostics: vscode.Diagnostic[] = [];
    const text = doc.getText();
    const sourceFile = ts.createSourceFile(doc.fileName, text, ts.ScriptTarget.Latest, true);

    function checkCSRF(node: ts.Node) {
      // Detect absence of csrf middleware in app.use
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === 'use'
      ) {
        const args = node.arguments.map(arg => arg.getText());
        const usesCsrf = args.some(arg => arg.toLowerCase().includes('csrf'));

        if (!usesCsrf && args.some(arg => /bodyparser|urlencoded|json/i.test(arg))) {
          const start = doc.positionAt(node.getStart());
          const end = doc.positionAt(node.getEnd());
          diagnostics.push(new vscode.Diagnostic(
            new vscode.Range(start, end),
            `🛡️ [SnitchLint-CSRF] Possible lack of CSRF protection middleware.`,
            vscode.DiagnosticSeverity.Warning
          ));
        }
      }

      ts.forEachChild(node, checkCSRF);
    }

    checkCSRF(sourceFile);
    return diagnostics;
  }
};
