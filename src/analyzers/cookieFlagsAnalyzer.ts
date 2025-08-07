import * as ts from 'typescript';
import * as vscode from 'vscode';
import { Analyzer } from '../core/analyzerTypes';

export const cookieFlagsAnalyzer: Analyzer = {
  id: 'insecure-cookie-flags',
  run: (doc) => {
    const diagnostics: vscode.Diagnostic[] = [];
    const sourceFile = ts.createSourceFile(doc.fileName, doc.getText(), ts.ScriptTarget.Latest, true);

    function checkCookies(node: ts.Node) {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === 'cookie'
      ) {
        const secondArg = node.arguments[1];
        if (secondArg && ts.isObjectLiteralExpression(secondArg)) {
          const flags = secondArg.properties.map(p =>
            ts.isPropertyAssignment(p) && ts.isIdentifier(p.name) ? p.name.text : ''
          );
          const hasSecure = flags.includes('secure');
          const hasHttpOnly = flags.includes('httpOnly');

          if (!hasSecure || !hasHttpOnly) {
            const start = doc.positionAt(node.getStart());
            const end = doc.positionAt(node.getEnd());
            diagnostics.push(new vscode.Diagnostic(
              new vscode.Range(start, end),
              `🍪 [SnitchLint-Cookies] Missing ${
                !hasSecure && !hasHttpOnly
                  ? '`Secure` and `HttpOnly`'
                  : !hasSecure
                  ? '`Secure`'
                  : '`HttpOnly`'
              } flags in cookie.`,
              vscode.DiagnosticSeverity.Warning
            ));
          }
        }
      }

      ts.forEachChild(node, checkCookies);
    }

    checkCookies(sourceFile);
    return diagnostics;
  }
};
