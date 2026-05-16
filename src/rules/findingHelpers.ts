/** Helpers for rules that use taint analysis — emits Finding + structured taintFlow for AI panel. */
import type { Finding, OwaspCategory, RuleSeverity, TaintFlowStep } from '../types';
import { getRuleMetadata } from '../metadata/ruleMetadata';

export interface TaintFindingParams {
  readonly ruleId: string;
  readonly severity: RuleSeverity;
  readonly message: string;
  readonly suggestion?: string;
  readonly start: number;
  readonly end: number;
  readonly owasp: OwaspCategory;
  readonly origins: Iterable<string>;
  readonly sinkApi: string;
  readonly sinkCode?: string;
  readonly propagationNotes?: readonly string[];
}

/** Build a finding with CWE metadata and structured taint flow for the AI panel. */
export function buildTaintFinding(params: TaintFindingParams): Finding {
  const meta = getRuleMetadata(params.ruleId);
  const originList = [...params.origins];

  const taintFlow: TaintFlowStep[] = [];
  for (const origin of originList) {
    taintFlow.push({
      kind: 'source',
      description: `Untrusted input: ${origin}`,
      code: origin,
    });
  }
  for (const note of params.propagationNotes ?? []) {
    taintFlow.push({ kind: 'propagation', description: note, code: note });
  }
  if (originList.length === 0) {
    taintFlow.push({
      kind: 'source',
      description: 'User-controlled or environment input',
    });
  }
  taintFlow.push({
    kind: 'sink',
    description: `Dangerous API: ${params.sinkApi}`,
    code: params.sinkCode ?? params.sinkApi,
  });

  return {
    ruleId: params.ruleId,
    severity: params.severity,
    message: params.message,
    suggestion: params.suggestion,
    start: params.start,
    end: params.end,
    owasp: params.owasp,
    vulnerabilityType: meta?.vulnerabilityType,
    cweId: meta?.cweId,
    cweName: meta?.cweName,
    riskyApi: params.sinkApi,
    taintFlow,
  };
}
