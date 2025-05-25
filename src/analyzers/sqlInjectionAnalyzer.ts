import * as vscode from 'vscode';

/**
 * Analyzes a given JavaScript or TypeScript document for potential SQL injection vulnerabilities.
 *
 * This function scans for SQL query patterns that are dynamically constructed using string concatenation
 * or template literals. These patterns are commonly vulnerable to SQL injection if user input is not
 * sanitized or parameterized.
 *
 * @param doc The text document to analyze.
 * @returns An array of diagnostics representing potential SQL injection issues.
 */
export function analyzeSqlInjection(doc: vscode.TextDocument): vscode.Diagnostic[] {
  const diagnostics: vscode.Diagnostic[] = [];

  const text = doc.getText();

  // Regex pattern: Detects SQL queries built via concatenation or embedded expressions
  const sqlConcatPattern = /(['"`])[^'"`\n]*?(SELECT|INSERT|UPDATE|DELETE).*?(\+.*?)+.*?\1/gi;

  let match: RegExpExecArray | null;
  while ((match = sqlConcatPattern.exec(text)) !== null) {
    const start = doc.positionAt(match.index);
    const end = doc.positionAt(match.index + match[0].length);

    const diagnostic = new vscode.Diagnostic(
      new vscode.Range(start, end),
      '⚠️ Possible SQL Injection detected via dynamic query construction.',
      vscode.DiagnosticSeverity.Warning
    );

    diagnostics.push(diagnostic);
  }

  return diagnostics;
}
