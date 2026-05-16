/**
 * SnitchLint configuration model — safe to import from unit tests (no vscode dependency).
 */

export interface SnitchLintAiConfiguration {
  readonly ollamaEnabled: boolean;
  readonly ollamaUrl: string;
  readonly ollamaModel: string;
  readonly useVsCodeLm: boolean;
}

export interface SnitchLintConfiguration {
  readonly enabled: boolean;
  readonly debounceMs: number;
  readonly logLevel: 'off' | 'error' | 'warn' | 'info' | 'debug';
  /** Explicit per-rule toggles; missing key means default true. */
  readonly ruleOverrides: Readonly<Record<string, boolean>>;
  readonly ai: SnitchLintAiConfiguration;
  isRuleEnabled(ruleId: string): boolean;
}

/** For unit tests and tooling without the VS Code API. */
export function createTestConfiguration(
  overrides?: Partial<Pick<SnitchLintConfiguration, 'enabled' | 'debounceMs' | 'logLevel' | 'ruleOverrides'>>
): SnitchLintConfiguration {
  const ruleOverrides = overrides?.ruleOverrides ?? {};
  const enabled = overrides?.enabled ?? true;
  return {
    enabled,
    debounceMs: overrides?.debounceMs ?? 400,
    logLevel: overrides?.logLevel ?? 'off',
    ruleOverrides,
    ai: {
      ollamaEnabled: false,
      ollamaUrl: 'http://127.0.0.1:11434',
      ollamaModel: 'llama3.2',
      useVsCodeLm: false,
    },
    isRuleEnabled(ruleId: string): boolean {
      if (!enabled) {
        return false;
      }
      return ruleOverrides[ruleId] !== false;
    },
  };
}
