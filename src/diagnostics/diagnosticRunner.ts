import * as vscode from 'vscode';
import { analyzeSqlInjection } from '../analyzers/sqlInjectionAnalyzer';

/**
 * Responsible for running all active diagnostics on the given document
 * and updating the VS Code diagnostic collection with results.
 *
 * This runner is designed to be scalable — as new analyzers (e.g., for XSS,
 * insecure deserialization, etc.) are added, they can be plugged in here.
 *
 * @param doc The text document to analyze.
 * @param collection The diagnostic collection to update.
 */
export function runDiagnostics(doc: vscode.TextDocument, collection: vscode.DiagnosticCollection): void {
  // Only target JavaScript and TypeScript for now
  if (!['javascript', 'typescript'].includes(doc.languageId)) {
    return;
  }

  const allDiagnostics: vscode.Diagnostic[] = [];

  // === Run All Analyzers ===
  // Add more analyzers here as needed.
  allDiagnostics.push(...analyzeSqlInjection(doc));

  // Update diagnostics in VS Code for the current document
  collection.set(doc.uri, allDiagnostics);
}
