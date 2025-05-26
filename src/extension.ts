import * as vscode from 'vscode';
import { runDiagnostics } from './diagnostics/diagnosticRunner';

/**
 * This function is called when the VS Code extension is activated.
 * It sets up listeners to trigger static analysis when documents are opened or changed.
 *
 * @param context VS Code extension context used for subscription and lifecycle management
 */
export function activate(context: vscode.ExtensionContext): void {
  const diagnosticCollection = vscode.languages.createDiagnosticCollection('snitchlint'); // Or your chosen name like 'sqlInjectionLinter'
  context.subscriptions.push(diagnosticCollection);

  /**
   * Triggers the static analysis pipeline on a given document.
   *
   * @param doc The text document to analyze
   */
  const analyzeDocument = (doc: vscode.TextDocument): void => {
    // Only analyze JavaScript and TypeScript files, as handled in diagnosticRunner
    if (['javascript', 'typescript'].includes(doc.languageId)) {
        runDiagnostics(doc, diagnosticCollection);
    } else {
        // Optionally clear diagnostics for non-JS/TS files if they were previously analyzed
        diagnosticCollection.delete(doc.uri);
    }
  };

  // Analyze all currently open documents when the extension activates
  if (vscode.window.activeTextEditor) {
    analyzeDocument(vscode.window.activeTextEditor.document);
  }
  vscode.workspace.textDocuments.forEach(analyzeDocument);


  // Analyze when a new document is opened or focused
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(analyzeDocument)
  );
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(editor => {
        if (editor) {
            analyzeDocument(editor.document);
        }
    })
  );


  // Analyze when a document changes (with a debounce to avoid too frequent updates)
  let timeout: NodeJS.Timeout | undefined = undefined;
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(event => {
      if (timeout) {
        clearTimeout(timeout);
      }
      timeout = setTimeout(() => {
        analyzeDocument(event.document);
      }, 500); // Debounce time in milliseconds
    })
  );

  // Clear diagnostics for closed documents
  context.subscriptions.push(
      vscode.workspace.onDidCloseTextDocument(doc => diagnosticCollection.delete(doc.uri))
  );

  console.log('✅ SQL Injection Linter extension activated and listening for changes.');
}

/**
 * This function is called when the extension is deactivated.
 * It can be used for cleanup if needed.
 */
export function deactivate(): void {
  console.log('❌ SQL Injection Linter extension deactivated.');
}