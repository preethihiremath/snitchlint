import * as ts from 'typescript';
import * as vscode from 'vscode';
import { Analyzer } from '../core/analyzerTypes';

const SECRET_PATTERNS = [
  /sk_live_[a-zA-Z0-9]{16,}/,
  /sk_test_[a-zA-Z0-9]{16,}/,
  /eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+/, // JWT
  /[a-zA-Z0-9]{32,}/ // generic long secrets
];

export const secretAnalyzer: Analyzer = {
  id: 'hardcoded-secrets',
  run: (doc) => {
    const diagnostics: vscode.Diagnostic[] = [];
    const sourceFile = ts.createSourceFile(doc.fileName, doc.getText(), ts.ScriptTarget.Latest, true);

    function checkSecrets(node: ts.Node) {
      // Look for variable declarations like: const apiKey = "something"
      if (ts.isVariableDeclaration(node) && node.initializer && ts.isStringLiteral(node.initializer)) {
        const varName = node.name.getText();
        const value = node.initializer.getText(); // includes quotes
        const combined = `${varName} = ${value}`;

        for (const pattern of SECRET_PATTERNS) {
          if (pattern.test(combined)) {
            const start = doc.positionAt(node.initializer.getStart());
            const end = doc.positionAt(node.initializer.getEnd());
            diagnostics.push(new vscode.Diagnostic(
              new vscode.Range(start, end),
              `🔒 [SnitchLint-Secrets] Hardcoded secret detected in "${varName}".`,
              vscode.DiagnosticSeverity.Warning
            ));
            break;
          }
        }
      }

      ts.forEachChild(node, checkSecrets);
    }


    checkSecrets(sourceFile);
    return diagnostics;
  }
};
