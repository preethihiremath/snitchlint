import * as ts from 'typescript';
import * as vscode from 'vscode';
import { Analyzer } from '../core/analyzerTypes';
import { TAINT_SOURCES } from '../utils/astUtils';

export const xssAnalyzer: Analyzer = {
  id: 'xss',
  run: (doc) => {
    const diagnostics: vscode.Diagnostic[] = [];
    const sourceFile = ts.createSourceFile(doc.fileName, doc.getText(), ts.ScriptTarget.Latest, true);

    const taintMap = new Map<string, boolean>();

    // Step 1: Collect all tainted variable declarations
    function collectTaints(node: ts.Node) {
      if (
        ts.isVariableDeclaration(node) &&
        node.initializer &&
        ts.isPropertyAccessExpression(node.initializer)
      ) {
        const initText = node.initializer.getText();
        if (TAINT_SOURCES.some(src => initText.includes(src))) {
          taintMap.set(node.name.getText(), true);
        }
      }
      ts.forEachChild(node, collectTaints);
    }

    // Step 2: Analyze usage of tainted values
    function checkXSS(node: ts.Node) {
      // case: element.innerHTML = taintedValue
      if (
        ts.isBinaryExpression(node) &&
        ts.isPropertyAccessExpression(node.left) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        node.left.name.text === 'innerHTML'
      ) {
        const rhs = node.right;
        const rhsText = rhs.getText();

        const isTainted =
          TAINT_SOURCES.some(src => rhsText.includes(src)) ||
          (ts.isIdentifier(rhs) && taintMap.has(rhs.text));

        if (isTainted) {
          const start = doc.positionAt(rhs.getStart());
          const end = doc.positionAt(rhs.getEnd());
          diagnostics.push(new vscode.Diagnostic(
            new vscode.Range(start, end),
            `⚠️ [SnitchLint-XSS] Potential XSS via innerHTML from "${rhsText}"`,
            vscode.DiagnosticSeverity.Warning
          ));
        }
      }

      // case: document.write(taintedValue)
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === 'write'
      ) {
        const arg = node.arguments[0];
        if (arg) {
          const argText = arg.getText();
          const isTainted =
            TAINT_SOURCES.some(src => argText.includes(src)) ||
            (ts.isIdentifier(arg) && taintMap.has(arg.text));

          if (isTainted) {
            const start = doc.positionAt(arg.getStart());
            const end = doc.positionAt(arg.getEnd());
            diagnostics.push(new vscode.Diagnostic(
              new vscode.Range(start, end),
              `⚠️ [SnitchLint-XSS] Potential XSS via document.write using "${argText}"`,
              vscode.DiagnosticSeverity.Warning
            ));
          }
        }
      }

      ts.forEachChild(node, checkXSS);
    }

    collectTaints(sourceFile);
    checkXSS(sourceFile);
    return diagnostics;
  }
};
