/** Maps engine Finding[] to vscode.Diagnostic[] for the Problems panel; honors snitchlint-ignore. */
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

function findIgnoreDirective(doc: vscode.TextDocument, line: number, ruleId: string): boolean {
  for (let l = Math.max(0, line); l >= Math.max(0, line - 1); l--) {
    const text = doc.lineAt(l).text;
    if (!text.includes('snitchlint-ignore')) continue;

    // Supported:
    // - // snitchlint-ignore: rule-id
    // - // snitchlint-ignore
    const m = text.match(/snitchlint-ignore\s*:\s*([a-zA-Z0-9-]+)/);
    if (!m) {
      // Bare ignore comment -> ignore all findings on this line.
      return true;
    }
    const ignoredRuleId = m[1];
    if (ignoredRuleId === '*' || ignoredRuleId === ruleId) return true;
  }
  return false;
}

/**
 * Maps engine findings to VS Code diagnostics with stable codes and optional remediation.
 */
export function findingsToDiagnostics(doc: vscode.TextDocument, findings: readonly Finding[]): vscode.Diagnostic[] {
  const len = doc.getText().length;
  return findings
    .map((f) => {
    const start = Math.max(0, Math.min(f.start, len));
    const end = Math.max(start, Math.min(f.end, len));
    const range = new vscode.Range(doc.positionAt(start), doc.positionAt(end));
    if (findIgnoreDirective(doc, range.start.line, f.ruleId)) {
      return undefined;
    }
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
    })
    .filter((d): d is vscode.Diagnostic => d !== undefined);
}
