import * as ts from 'typescript';
import * as vscode from 'vscode';
import { Analyzer } from '../core/analyzerTypes';

export const evalFunctionAnalyzer: Analyzer = {
  id: 'insecure-eval-function',
  run: (doc) => {
    const diagnostics: vscode.Diagnostic[] = [];
    const sourceFile = ts.createSourceFile(doc.fileName, doc.getText(), ts.ScriptTarget.Latest, true);

    function checkInsecureEval(node: ts.Node) {
      // eval()
      if (
        ts.isCallExpression(node) &&
        ts.isIdentifier(node.expression) &&
        node.expression.text === 'eval'
      ) {
        const argText = node.arguments[0]?.getText() || '';
        if (/req|input|param|user/i.test(argText)) {
          const start = doc.positionAt(node.getStart());
          const end = doc.positionAt(node.getEnd());
          diagnostics.push(new vscode.Diagnostic(
            new vscode.Range(start, end),
            `🧨 [SnitchLint-Eval] Avoid using eval() with dynamic or untrusted input.`,
            vscode.DiagnosticSeverity.Error
          ));
        }
      }

      // new Function()
      if (
        ts.isNewExpression(node) &&
        ts.isIdentifier(node.expression) &&
        node.expression.text === 'Function'
      ) {
        const argsText = node.arguments?.map(arg => arg.getText()).join(', ') || '';
        if (/req|input|param|user/i.test(argsText)) {
          const start = doc.positionAt(node.getStart());
          const end = doc.positionAt(node.getEnd());
          diagnostics.push(new vscode.Diagnostic(
            new vscode.Range(start, end),
            `🧨 [SnitchLint-Eval] Avoid using new Function() with dynamic input.`,
            vscode.DiagnosticSeverity.Error
          ));
        }
      }

      ts.forEachChild(node, checkInsecureEval);
    }

    checkInsecureEval(sourceFile);
    return diagnostics;
  }
};
