import * as vscode from 'vscode';
import { runDiagnostics } from './diagnostics/diagnosticRunner';

/**
 * This function is called when the VS Code extension is activated.
 * It sets up listeners to trigger static analysis when documents are opened or changed.
 *
 * @param context VS Code extension context used for subscription and lifecycle management
 */
export function activate(context: vscode.ExtensionContext): void {
  const diagnosticCollection = vscode.languages.createDiagnosticCollection('snitchlint');
  context.subscriptions.push(diagnosticCollection);

  /**
   * Triggers the static analysis pipeline on a given document.
   *
   * @param doc The text document to analyze
   */
  const analyzeDocument = (doc: vscode.TextDocument): void => {
    runDiagnostics(doc, diagnosticCollection);
  };

  // Analyze all currently open documents when the extension activates
  vscode.workspace.textDocuments.forEach(analyzeDocument);

  // Analyze when a new document is opened
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(analyzeDocument)
  );

  // Analyze when a document changes
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(event => {
      analyzeDocument(event.document);
    })
  );

  console.log('✅ SnitchLint extension activated and listening for changes.');
}

/**
 * This function is called when the extension is deactivated.
 * It can be used for cleanup if needed.
 */
export function deactivate(): void {
  console.log('❌ SnitchLint extension deactivated.');
}
