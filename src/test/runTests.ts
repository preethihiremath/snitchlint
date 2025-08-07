import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

import { analyzerRegistry } from '../core/analyzerRegistry';

function createFakeDocument(filePath: string): vscode.TextDocument {
  const content = fs.readFileSync(filePath, 'utf-8');

  return {
    uri: vscode.Uri.file(filePath),
    fileName: filePath,
    getText: () => content,
    languageId: 'typescript',
    lineCount: content.split('\n').length,
    // fake methods
    positionAt(offset: number): vscode.Position {
      const lines = content.substring(0, offset).split('\n');
      const line = lines.length - 1;
      const character = lines[line].length;
      return new vscode.Position(line, character);
    },
    // mock implementations (not needed for analysis)
    isClosed: false,
    version: 1,
    eol: vscode.EndOfLine.LF,
    save: async () => true,
    lineAt: () => { throw new Error("Not implemented."); },
    getWordRangeAtPosition: () => undefined,
    validateRange: () => { throw new Error("Not implemented."); },
    validatePosition: () => { throw new Error("Not implemented."); }
  } as unknown as vscode.TextDocument;
}

function runTests() {
  const fixturesDir = path.join(__dirname, 'fixtures');
  const files = fs.readdirSync(fixturesDir).filter(f => f.endsWith('.ts'));

  for (const file of files) {
    const fullPath = path.join(fixturesDir, file);
    const doc = createFakeDocument(fullPath);
    console.log(`\n🧪 Testing file: ${file}`);

    for (const analyzer of analyzerRegistry) {
      const results = analyzer.run(doc);
      if (results.length > 0) {
        console.log(`  ✅ ${analyzer.id} flagged ${results.length} issue(s):`);
        for (const diag of results) {
          console.log(`    → ${diag.message}`);
        }
      } else {
        console.log(`  ⚠️ ${analyzer.id} found no issues.`);
      }
    }
  }
}

runTests();
