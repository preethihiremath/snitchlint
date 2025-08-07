import * as ts from 'typescript';
import * as vscode from 'vscode';
import { Analyzer } from '../core/analyzerTypes';

const WEAK_HASHES = ['md5', 'sha1'];

export const weakCryptoAnalyzer: Analyzer = {
  id: 'weak-crypto',
  run: (doc) => {
    const diagnostics: vscode.Diagnostic[] = [];
    const sourceFile = ts.createSourceFile(doc.fileName, doc.getText(), ts.ScriptTarget.Latest, true);

    function checkWeakCrypto(node: ts.Node) {
      // crypto.createHash('md5') or crypto.createHmac('sha1')
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        (node.expression.name.text === 'createHash' || node.expression.name.text === 'createHmac')
      ) {
        const firstArg = node.arguments[0];
        if (firstArg && ts.isStringLiteral(firstArg) && WEAK_HASHES.includes(firstArg.text.toLowerCase())) {
          const start = doc.positionAt(node.getStart());
          const end = doc.positionAt(node.getEnd());
          diagnostics.push(new vscode.Diagnostic(
            new vscode.Range(start, end),
            `🧯 [SnitchLint-Crypto] Usage of weak hash function "${firstArg.text}" detected.`,
            vscode.DiagnosticSeverity.Warning
          ));
        }
      }

      ts.forEachChild(node, checkWeakCrypto);
    }

    checkWeakCrypto(sourceFile);
    return diagnostics;
  }
};
