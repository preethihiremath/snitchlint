/**
 * Builds structured security explanations from Finding + ruleMetadata.
 * Used by AiInsightPanel; no network calls — deterministic offline text.
 */
import type { Finding } from '../types';
import { getRuleMetadata, getOwaspShortLabel } from '../metadata/ruleMetadata';

export interface SecurityExplanation {
  readonly summary: string;
  readonly whyVulnerable: string;
  readonly vulnerabilityType: string;
  readonly taintFlow: readonly { kind: string; label: string; code?: string }[];
  readonly owasp: string;
  readonly cweId: string;
  readonly cweName: string;
  readonly riskyApi: string;
  readonly riskyPatterns: readonly string[];
  readonly ruleId: string;
}

export function buildExplanation(finding: Finding): SecurityExplanation {
  const meta = getRuleMetadata(finding.ruleId);

  const vulnerabilityType = finding.vulnerabilityType ?? meta?.vulnerabilityType ?? 'Security Issue';
  const cweId = finding.cweId ?? meta?.cweId ?? '—';
  const cweName = finding.cweName ?? meta?.cweName ?? '—';
  const riskyApi = finding.riskyApi ?? meta?.defaultSinkLabel ?? '—';

  const taintFlow = (finding.taintFlow ?? []).map((step) => ({
    kind: step.kind,
    label: step.description,
    code: step.code,
  }));

  const whyVulnerable =
    meta?.whyItMatters ??
    finding.suggestion ??
    'This pattern can be exploited when attacker-controlled data reaches a sensitive operation without proper validation.';

  const summary = buildSummary(finding, vulnerabilityType, riskyApi);

  return {
    summary,
    whyVulnerable,
    vulnerabilityType,
    taintFlow,
    owasp: getOwaspShortLabel(finding.owasp),
    cweId,
    cweName,
    riskyApi,
    riskyPatterns: meta?.riskyPatterns ?? [],
    ruleId: finding.ruleId,
  };
}

function buildSummary(finding: Finding, vulnerabilityType: string, riskyApi: string): string {
  const hasFlow = finding.taintFlow && finding.taintFlow.length >= 2;
  if (hasFlow) {
    const source = finding.taintFlow!.find((s) => s.kind === 'source');
    const sink = finding.taintFlow!.find((s) => s.kind === 'sink');
    const srcLabel = source?.code ?? source?.description ?? 'untrusted input';
    const sinkLabel = sink?.code ?? sink?.description ?? riskyApi;
    return `${vulnerabilityType}: data from ${srcLabel} reaches ${sinkLabel} without adequate safeguards.`;
  }
  return `${vulnerabilityType}: ${finding.message}`;
}
