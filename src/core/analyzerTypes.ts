import * as vscode from 'vscode';

export interface Analyzer {
  id: string;
  run(doc: vscode.TextDocument): vscode.Diagnostic[];
}
