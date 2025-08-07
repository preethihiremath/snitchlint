import * as ts from 'typescript';
import * as vscode from 'vscode';
import { Analyzer } from '../core/analyzerTypes';

export const openRedirectAnalyzer: Analyzer = {
  id: 'open-redirect',
  run: (doc) => {
    const diagnostics: vscode.Diagnostic[] = [];
    const text = doc.getText();
    const sourceFile = ts.createSourceFile(doc.fileName, text, ts.ScriptTarget.Latest, true);

    function checkRedirect(node: ts.Node) {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === 'redirect' &&
        node.arguments.length > 0
      ) {
        const arg = node.arguments[0];
        const argText = arg.getText();
        if (/req\.query|req\.body|req\.params/.test(argText)) {
          const start = doc.positionAt(arg.getStart());
          const end = doc.positionAt(arg.getEnd());
          diagnostics.push(new vscode.Diagnostic(
            new vscode.Range(start, end),
            `🌐 [SnitchLint-Redirect] Open redirect vulnerability via unvalidated user input: ${argText}`,
            vscode.DiagnosticSeverity.Warning
          ));
        }
      }

      ts.forEachChild(node, checkRedirect);
    }

    checkRedirect(sourceFile);
    return diagnostics;
  }
};
