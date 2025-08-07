import * as ts from 'typescript';
import * as vscode from 'vscode';
import { Analyzer } from '../core/analyzerTypes';

export const fileUploadAnalyzer: Analyzer = {
  id: 'unrestricted-file-upload',
  run: (doc) => {
    const diagnostics: vscode.Diagnostic[] = [];
    const sourceFile = ts.createSourceFile(doc.fileName, doc.getText(), ts.ScriptTarget.Latest, true);

    function checkFileUpload(node: ts.Node) {
      // Detect multer.single(...) or any file-handler without validation
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === 'single' &&
        node.arguments.length > 0
      ) {
        const start = doc.positionAt(node.getStart());
        const end = doc.positionAt(node.getEnd());
        diagnostics.push(new vscode.Diagnostic(
          new vscode.Range(start, end),
          `📤 [SnitchLint-Upload] Possible unrestricted file upload detected. Validate file type and size.`,
          vscode.DiagnosticSeverity.Warning
        ));
      }

      ts.forEachChild(node, checkFileUpload);
    }

    checkFileUpload(sourceFile);
    return diagnostics;
  }
};
