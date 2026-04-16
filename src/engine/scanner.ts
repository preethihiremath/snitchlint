import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from '../rules/ruleTypes';
import { createSourceFileForScan } from './createSourceFile';
import type { SnitchLintConfiguration } from '../config/configuration';
import { TaintAnalyzer } from './taintAnalyzer';

export interface ScanInput {
  readonly fileName: string;
  readonly text: string;
  readonly languageId: string;
}

export interface ScanResult {
  readonly findings: readonly Finding[];
  readonly parseFailed?: boolean;
}

function isAnalyzableLanguage(languageId: string): boolean {
  return languageId === 'javascript' || languageId === 'typescript' || languageId === 'javascriptreact' || languageId === 'typescriptreact';
}

/**
 * Runs all registered rules with shared AST and per-rule error isolation.
 */
export function scanDocument(
  input: ScanInput,
  rules: readonly SecurityRule[],
  config: SnitchLintConfiguration,
  onRuleError: (ruleId: string, err: unknown) => void
): ScanResult {
  if (!config.enabled || !isAnalyzableLanguage(input.languageId)) {
    return { findings: [] };
  }

  let sourceFile;
  try {
    sourceFile = createSourceFileForScan(input.fileName, input.text);
  } catch {
    return { findings: [], parseFailed: true };
  }

  const ctx: RuleContext = {
    sourceFile,
    fileName: input.fileName,
    fullText: input.text,
    taint: new TaintAnalyzer(sourceFile),
    isRuleEnabled: (ruleId: string) => config.isRuleEnabled(ruleId),
  };

  const findings: Finding[] = [];

  for (const rule of rules) {
    if (!ctx.isRuleEnabled(rule.id)) {
      continue;
    }
    try {
      findings.push(...rule.analyze(ctx));
    } catch (err) {
      onRuleError(rule.id, err);
    }
  }

  return { findings };
}
