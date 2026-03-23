import * as vscode from 'vscode';
import { scanDocument } from './engine/scanner';
import { allSecurityRules } from './rules/registry';
import { getConfiguration } from './config/vscodeConfiguration';
import { findingsToDiagnostics } from './adapters/vscodeDiagnostics';
import { SnitchLintLogger } from './logging/logger';

export function activate(context: vscode.ExtensionContext): void {
  const logger = new SnitchLintLogger();
  logger.setLevel(getConfiguration().logLevel);
  context.subscriptions.push(logger);

  const diagnosticCollection = vscode.languages.createDiagnosticCollection('snitchlint');
  context.subscriptions.push(diagnosticCollection);

  let config = getConfiguration();

  const runAnalysis = (doc: vscode.TextDocument): void => {
    const langs = ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'];
    if (!langs.includes(doc.languageId)) {
      diagnosticCollection.delete(doc.uri);
      return;
    }

    const result = scanDocument(
      { fileName: doc.fileName, text: doc.getText(), languageId: doc.languageId },
      allSecurityRules,
      config,
      (ruleId, err) => {
        logger.error(`Rule "${ruleId}" failed`, err);
      }
    );

    if (result.parseFailed) {
      logger.debug(`Could not parse ${doc.fileName} — diagnostics cleared.`);
      diagnosticCollection.delete(doc.uri);
      return;
    }

    diagnosticCollection.set(doc.uri, findingsToDiagnostics(doc, result.findings));
    logger.debug(`Scan ${doc.fileName}: ${result.findings.length} finding(s)`);
  };

  let debounceTimer: ReturnType<typeof setTimeout> | undefined;

  const scheduleAnalysis = (doc: vscode.TextDocument): void => {
    if (debounceTimer) {
      clearTimeout(debounceTimer);
    }
    debounceTimer = setTimeout(() => {
      runAnalysis(doc);
      debounceTimer = undefined;
    }, config.debounceMs);
  };

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('snitchlint')) {
        config = getConfiguration();
        logger.setLevel(config.logLevel);
        if (vscode.window.activeTextEditor) {
          runAnalysis(vscode.window.activeTextEditor.document);
        }
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('snitchlint.scan', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        runAnalysis(editor.document);
      }
    })
  );

  const analyzeIfApplicable = (doc: vscode.TextDocument): void => {
    const langs = ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'];
    if (langs.includes(doc.languageId)) {
      runAnalysis(doc);
    } else {
      diagnosticCollection.delete(doc.uri);
    }
  };

  if (vscode.window.activeTextEditor) {
    analyzeIfApplicable(vscode.window.activeTextEditor.document);
  }
  vscode.workspace.textDocuments.forEach(analyzeIfApplicable);

  context.subscriptions.push(vscode.workspace.onDidOpenTextDocument(analyzeIfApplicable));
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor) {
        analyzeIfApplicable(editor.document);
      }
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      scheduleAnalysis(event.document);
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => {
      diagnosticCollection.delete(doc.uri);
    })
  );

  logger.info('SnitchLint activated — security analysis enabled for JS/TS.');
}

export function deactivate(): void {
  // Subscriptions disposed by VS Code
}
