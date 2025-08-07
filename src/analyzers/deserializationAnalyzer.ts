import * as ts from 'typescript';
import * as vscode from 'vscode';
import { Analyzer } from '../core/analyzerTypes';

export const deserializationAnalyzer: Analyzer = {
  id: 'insecure-deserialization',
  run: (doc) => {
    const diagnostics: vscode.Diagnostic[] = [];
    const sourceFile = ts.createSourceFile(doc.fileName, doc.getText(), ts.ScriptTarget.Latest, true);

    function checkDeserialization(node: ts.Node) {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.expression.getText() === 'JSON' &&
        node.expression.name.getText() === 'parse'
      ) {
        const argText = node.arguments[0]?.getText() || '';
        if (/req|input|param|user/i.test(argText)) {
          const start = doc.positionAt(node.getStart());
          const end = doc.positionAt(node.getEnd());
          diagnostics.push(new vscode.Diagnostic(
            new vscode.Range(start, end),
            `🧬 [SnitchLint-Deserialization] Avoid insecure deserialization of untrusted input.`,
            vscode.DiagnosticSeverity.Warning
          ));
        }
      }

      ts.forEachChild(node, checkDeserialization);
    }

    checkDeserialization(sourceFile);
    return diagnostics;
  }
};
