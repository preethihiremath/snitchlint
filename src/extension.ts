/**
 * VS Code extension entry point.
 *
 * Responsibilities:
 * - Subscribe to document open/change/active editor events
 * - Run scanDocument() and push results to the Problems panel
 * - Cache findings per URI (versioned) for the AI Insight panel
 * - Register commands: scan, SARIF export, explain & suggest fix
 * - Provide code actions: ignore directive + open AI panel
 */
import * as vscode from 'vscode';
import { scanDocument } from './engine/scanner';
import { allSecurityRules } from './rules/registry';
import { getConfiguration } from './config/vscodeConfiguration';
import { findingsToDiagnostics } from './adapters/vscodeDiagnostics';
import { SnitchLintLogger } from './logging/logger';
import { AiInsightPanel, type AiInsightPayload } from './ui/aiInsightPanel';
import type { Finding } from './types';

export function activate(context: vscode.ExtensionContext): void {
  const logger = new SnitchLintLogger();
  logger.setLevel(getConfiguration().logLevel);
  context.subscriptions.push(logger);

  const diagnosticCollection = vscode.languages.createDiagnosticCollection('snitchlint');
  context.subscriptions.push(diagnosticCollection);

  let config = getConfiguration();
  /** Last scan per file; document.version invalidates cache on edit. */
  const scanCache = new Map<string, { version: number; findings: readonly Finding[] }>();

  /** Parse + run rules + set diagnostics; skips unsupported languages. */
  const runAnalysis = (doc: vscode.TextDocument): void => {
    const langs = ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'];
    if (!langs.includes(doc.languageId)) {
      diagnosticCollection.delete(doc.uri);
      return;
    }

    const cacheKey = doc.uri.toString();
    const cached = scanCache.get(cacheKey);
    if (cached && cached.version === doc.version) {
      diagnosticCollection.set(doc.uri, findingsToDiagnostics(doc, cached.findings));
      logger.debug(`Scan ${doc.fileName}: ${cached.findings.length} finding(s) (cached)`);
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

    scanCache.set(cacheKey, { version: doc.version, findings: result.findings });
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
        scanCache.clear();
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

  /** Resolve the Finding under the cursor from the cached scan (for AI panel). */
  const findFindingAtPosition = (
    doc: vscode.TextDocument,
    position: vscode.Position
  ): Finding | undefined => {
    const offset = doc.offsetAt(position);
    const cached = scanCache.get(doc.uri.toString());
    if (!cached) return undefined;
    return cached.findings.find((f) => offset >= f.start && offset <= f.end);
  };

  /** Replace the entire line containing the finding when fix.canApply is true. */
  const applyFixToEditor = async (payload: AiInsightPayload): Promise<void> => {
    const editor = vscode.window.activeTextEditor;
    if (!editor || !payload.fix.canApply) {
      return;
    }
    const doc = editor.document;
    const line = doc.lineAt(doc.positionAt(payload.findingStart).line);
    const edit = new vscode.WorkspaceEdit();
    edit.replace(doc.uri, line.range, payload.fix.after);
    const ok = await vscode.workspace.applyEdit(edit);
    if (ok) {
      vscode.window.showInformationMessage('SnitchLint: Secure fix applied.');
      runAnalysis(doc);
    }
  };

  const showAiInsight = async (finding?: Finding): Promise<void> => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage('SnitchLint: Open a JS/TS file to view AI security insight.');
      return;
    }
    const doc = editor.document;
    const target =
      finding ??
      (editor.selection.isEmpty
        ? findFindingAtPosition(doc, editor.selection.active)
        : scanCache
            .get(doc.uri.toString())
            ?.findings.find((f) => {
              const selStart = doc.offsetAt(editor.selection.start);
              const selEnd = doc.offsetAt(editor.selection.end);
              return f.start <= selEnd && f.end >= selStart;
            }));

    if (!target) {
      vscode.window.showWarningMessage(
        'SnitchLint: Place the cursor on a SnitchLint finding (Problems panel) and try again.'
      );
      return;
    }

    await AiInsightPanel.show(
      context,
      doc,
      target,
      {
        ollamaEnabled: config.ai.ollamaEnabled,
        ollamaUrl: config.ai.ollamaUrl,
        ollamaModel: config.ai.ollamaModel,
        useVsCodeLm: config.ai.useVsCodeLm,
      },
      applyFixToEditor
    );
  };

  context.subscriptions.push(
    vscode.commands.registerCommand('snitchlint.showAiInsight', () => showAiInsight())
  );

  // Quick Fix: insert `snitchlint-ignore: <ruleId>` above the diagnostic line.
  const hasIgnore = (document: vscode.TextDocument, line: number, ruleId: string): boolean => {
    for (let l = Math.max(0, line); l >= Math.max(0, line - 1); l--) {
      const text = document.lineAt(l).text;
      if (!text.includes('snitchlint-ignore')) continue;
      const m = text.match(/snitchlint-ignore\s*:\s*([a-zA-Z0-9-]+)/);
      if (!m) return true;
      const ignoredRuleId = m[1];
      if (ignoredRuleId === '*' || ignoredRuleId === ruleId) return true;
    }
    return false;
  };

  const codeActionProvider: vscode.CodeActionProvider = {
    provideCodeActions(document, _range, context) {
      const actions: vscode.CodeAction[] = [];
      for (const diag of context.diagnostics) {
        if (diag.source !== 'SnitchLint') continue;
        const code = diag.code;
        if (!code) continue;
        const ruleId = String(code);
        const line = diag.range.start.line;
        if (hasIgnore(document, line, ruleId)) continue;

        const edit = new vscode.WorkspaceEdit();
        const insertPos = new vscode.Position(line, 0);
        edit.set(document.uri, [vscode.TextEdit.insert(insertPos, `// snitchlint-ignore: ${ruleId}\n`)]);

        const action = new vscode.CodeAction(`SnitchLint: Ignore ${ruleId}`, vscode.CodeActionKind.QuickFix);
        action.edit = edit;
        action.diagnostics = [diag];
        action.isPreferred = true;
        actions.push(action);

        const explainAction = new vscode.CodeAction(
          'SnitchLint: Explain & Suggest Fix',
          vscode.CodeActionKind.Empty
        );
        explainAction.command = {
          title: 'Explain & Suggest Fix',
          command: 'snitchlint.showAiInsightForDiagnostic',
          arguments: [document.uri.toString(), diag.range.start.line, diag.range.start.character, ruleId],
        };
        explainAction.diagnostics = [diag];
        actions.push(explainAction);
      }
      return actions;
    },
  };

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'],
      codeActionProvider,
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix, vscode.CodeActionKind.Empty] }
    )
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(
      'snitchlint.showAiInsightForDiagnostic',
      async (uriStr: string, line: number, character: number, ruleId: string) => {
        const uri = vscode.Uri.parse(uriStr);
        const doc = await vscode.workspace.openTextDocument(uri);
        const pos = new vscode.Position(line, character);
        const offset = doc.offsetAt(pos);
        const cached = scanCache.get(uriStr);
        const finding = cached?.findings.find(
          (f) => f.ruleId === ruleId && offset >= f.start && offset <= f.end
        );
        if (finding) {
          await vscode.window.showTextDocument(doc, { selection: new vscode.Range(pos, pos) });
          await showAiInsight(finding);
        } else {
          runAnalysis(doc);
          vscode.window.showWarningMessage('SnitchLint: Re-scan the file and try again.');
        }
      }
    )
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('snitchlint.scanWorkspace', async () => {
      const folder = vscode.workspace.workspaceFolders?.[0];
      if (!folder) {
        vscode.window.showErrorMessage('SnitchLint: No workspace folder found.');
        return;
      }

      const files = await vscode.workspace.findFiles('**/*.{ts,tsx,js,jsx}', '**/node_modules/**');

      const sarifRules = allSecurityRules.map((r) => ({
        id: r.id,
        name: r.title,
        shortDescription: { text: r.description },
        fullDescription: { text: r.title },
      }));

      const results: any[] = [];

      const toLineColumn = (text: string, offset: number): { line: number; column: number } => {
        const off = Math.max(0, Math.min(offset, text.length));
        let line = 1;
        let column = 1;
        for (let i = 0; i < off; i++) {
          const ch = text.charCodeAt(i);
          if (ch === 10 /* \n */) {
            line++;
            column = 1;
          } else if (ch !== 13 /* \r */) {
            column++;
          }
        }
        return { line, column };
      };

      for (const uri of files) {
        const buf = await vscode.workspace.fs.readFile(uri);
        const text = Buffer.from(buf).toString('utf8');

        const path = uri.path.toLowerCase();
        let languageId: string;
        if (path.endsWith('.ts')) languageId = 'typescript';
        else if (path.endsWith('.tsx')) languageId = 'typescriptreact';
        else if (path.endsWith('.js')) languageId = 'javascript';
        else languageId = 'javascriptreact';

        const result = scanDocument(
          { fileName: uri.fsPath, text, languageId },
          allSecurityRules,
          config,
          () => {
            /* ignore rule errors in workspace export */
          }
        );

        if (result.parseFailed || result.findings.length === 0) continue;

        for (const f of result.findings) {
          const start = toLineColumn(text, f.start);
          const end = toLineColumn(text, f.end);

          results.push({
            ruleId: f.ruleId,
            level: f.severity === 'error' ? 'error' : f.severity === 'warning' ? 'warning' : f.severity === 'information' ? 'note' : 'none',
            message: { text: f.message },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: uri.toString() },
                  region: {
                    startLine: start.line,
                    startColumn: start.column,
                    endLine: end.line,
                    endColumn: Math.max(start.column + 1, end.column),
                  },
                },
              },
            ],
          });
        }
      }

      const sarif = {
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: {
                name: 'SnitchLint',
                rules: sarifRules,
              },
            },
            results,
          },
        ],
      };

      const outUri = vscode.Uri.joinPath(folder.uri, 'snitchlint.sarif');
      const outJson = Buffer.from(JSON.stringify(sarif, null, 2), 'utf8');
      await vscode.workspace.fs.writeFile(outUri, outJson);
      vscode.window.showInformationMessage(`SnitchLint: SARIF written to ${outUri.fsPath}`);
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
