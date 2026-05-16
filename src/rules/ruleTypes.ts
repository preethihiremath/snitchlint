import type * as ts from 'typescript';
import type { Finding, OwaspCategory } from '../types';
import type { TaintAnalyzer } from '../engine/taintAnalyzer';

/**
 * Context passed to every rule — one AST parse per document, shared across rules.
 */
export interface RuleContext {
  readonly sourceFile: ts.SourceFile;
  readonly fileName: string;
  readonly fullText: string;
  readonly taint: TaintAnalyzer;
  isRuleEnabled(ruleId: string): boolean;
}

export interface SecurityRuleMeta {
  readonly id: string;
  readonly title: string;
  readonly owasp: OwaspCategory;
  /** Short description for settings / docs. */
  readonly description: string;
}

export interface SecurityRule extends SecurityRuleMeta {
  analyze(ctx: RuleContext): readonly Finding[];
}
