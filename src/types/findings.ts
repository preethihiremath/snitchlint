/**
 * Core finding model — independent of VS Code for unit testing and reuse.
 * Extended in v0.2 with taintFlow + CWE fields for the AI Insight panel.
 */

export type RuleSeverity = 'error' | 'warning' | 'information' | 'hint';

/** OWASP Top 10 (2021) mapping for rules; used in diagnostics and docs. */
export type OwaspCategory =
  | 'A01:2021-Broken Access Control'
  | 'A02:2021-Cryptographic Failures'
  | 'A03:2021-Injection'
  | 'A04:2021-Insecure Design'
  | 'A05:2021-Security Misconfiguration'
  | 'A06:2021-Vulnerable and Outdated Components'
  | 'A07:2021-Identification and Authentication Failures'
  | 'A08:2021-Software and Data Integrity Failures'
  | 'A09:2021-Security Logging and Monitoring Failures'
  | 'A10:2021-Server-Side Request Forgery';

export type TaintFlowStepKind = 'source' | 'propagation' | 'sink';

/** One step in source → propagation → sink data flow. */
export interface TaintFlowStep {
  readonly kind: TaintFlowStepKind;
  readonly description: string;
  /** Optional code fragment for this step. */
  readonly code?: string;
}

export interface Finding {
  readonly ruleId: string;
  readonly severity: RuleSeverity;
  /** Primary user-facing message (no emoji noise; VS Code shows severity separately). */
  readonly message: string;
  /** Optional remediation hint. */
  readonly suggestion?: string;
  /** Byte offsets into the document (UTF-16 code units, aligned with TypeScript). */
  readonly start: number;
  readonly end: number;
  readonly owasp?: OwaspCategory;
  /** Human-readable vulnerability class (e.g. SQL Injection). */
  readonly vulnerabilityType?: string;
  readonly cweId?: string;
  readonly cweName?: string;
  readonly riskyApi?: string;
  readonly taintFlow?: readonly TaintFlowStep[];
}
