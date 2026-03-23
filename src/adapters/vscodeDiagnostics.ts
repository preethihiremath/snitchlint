import * as vscode from 'vscode';
import type { Finding, RuleSeverity } from '../types';

function toVsSeverity(s: RuleSeverity): vscode.DiagnosticSeverity {
  switch (s) {
    case 'error':
      return vscode.DiagnosticSeverity.Error;
    case 'warning':
      return vscode.DiagnosticSeverity.Warning;
    case 'information':
      return vscode.DiagnosticSeverity.Information;
    case 'hint':
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

/**
 * Maps engine findings to VS Code diagnostics with stable codes and optional remediation.
 */
export function findingsToDiagnostics(doc: vscode.TextDocument, findings: readonly Finding[]): vscode.Diagnostic[] {
  const len = doc.getText().length;
  return findings.map((f) => {
    const start = Math.max(0, Math.min(f.start, len));
    const end = Math.max(start, Math.min(f.end, len));
    const range = new vscode.Range(doc.positionAt(start), doc.positionAt(end));
    const diag = new vscode.Diagnostic(range, f.message, toVsSeverity(f.severity));
    diag.source = 'SnitchLint';
    diag.code = f.ruleId;
    diag.tags = f.severity === 'hint' ? [vscode.DiagnosticTag.Unnecessary] : undefined;
    if (f.suggestion) {
      diag.relatedInformation = [
        new vscode.DiagnosticRelatedInformation(
          new vscode.Location(doc.uri, range),
          `Suggestion: ${f.suggestion}`
        ),
      ];
    }
    return diag;
  });
}
