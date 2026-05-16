/**
 * Post-scan pass: attach CWE, vulnerability type, and taint flow when rules omit them.
 * Parses origin/sink hints from finding.message as a fallback.
 */
import type { Finding, TaintFlowStep } from '../types';
import { getRuleMetadata } from '../metadata/ruleMetadata';

const ORIGIN_IN_MESSAGE = /(?:from|influenced by)\s+"([^"]+)"/i;
const SQL_METHOD_IN_MESSAGE = /method\s+"([^"]+)"/i;
const COMMAND_FN_IN_MESSAGE = /:\s*(\w+)\s+argument/i;

function inferTaintFlowFromMessage(finding: Finding): readonly TaintFlowStep[] | undefined {
  if (finding.taintFlow && finding.taintFlow.length > 0) {
    return finding.taintFlow;
  }

  const meta = getRuleMetadata(finding.ruleId);
  const steps: TaintFlowStep[] = [];
  const originMatch = finding.message.match(ORIGIN_IN_MESSAGE);
  const sqlMethod = finding.message.match(SQL_METHOD_IN_MESSAGE);
  const cmdFn = finding.message.match(COMMAND_FN_IN_MESSAGE);

  if (originMatch) {
    steps.push({
      kind: 'source',
      description: `Untrusted input: ${originMatch[1]}`,
      code: originMatch[1],
    });
    steps.push({
      kind: 'propagation',
      description: 'Value flows through assignments, parameters, or return values without sanitization',
    });
  } else if (/untrusted|user-influenced|tainted/i.test(finding.message)) {
    steps.push({
      kind: 'source',
      description: 'User-controlled or untrusted input',
    });
    steps.push({
      kind: 'propagation',
      description: 'Data propagates to the sink without validation or encoding',
    });
  }

  const sinkApi =
    finding.riskyApi ??
    sqlMethod?.[1] ??
    (cmdFn ? `child_process.${cmdFn[1]}` : undefined) ??
    meta?.defaultSinkLabel;

  if (sinkApi) {
    steps.push({
      kind: 'sink',
      description: `Dangerous API: ${sinkApi}`,
      code: sinkApi,
    });
  }

  return steps.length > 0 ? steps : undefined;
}

/** Attach CWE, vulnerability type, and taint flow when rules omit structured fields. */
export function enrichFinding(finding: Finding): Finding {
  const meta = getRuleMetadata(finding.ruleId);
  if (!meta) {
    return finding;
  }

  const taintFlow = inferTaintFlowFromMessage(finding);

  return {
    ...finding,
    vulnerabilityType: finding.vulnerabilityType ?? meta.vulnerabilityType,
    cweId: finding.cweId ?? meta.cweId,
    cweName: finding.cweName ?? meta.cweName,
    riskyApi: finding.riskyApi ?? taintFlow?.find((s) => s.kind === 'sink')?.code ?? meta.defaultSinkLabel,
    taintFlow: finding.taintFlow ?? taintFlow,
    owasp: finding.owasp,
  };
}

export function enrichFindings(findings: readonly Finding[]): readonly Finding[] {
  return findings.map(enrichFinding);
}
