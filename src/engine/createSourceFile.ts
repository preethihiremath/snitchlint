import * as ts from 'typescript';

/**
 * Single entry point for parsing JS/TS — avoids duplicate work across rules.
 */
export function createSourceFileForScan(fileName: string, text: string): ts.SourceFile {
  return ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
}
