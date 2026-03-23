import * as vscode from 'vscode';
import type { SnitchLintConfiguration } from './configuration';

const SECTION = 'snitchlint';

function readRuleOverrides(config: vscode.WorkspaceConfiguration): Record<string, boolean> {
  const raw = config.get<Record<string, boolean>>('rules');
  return raw && typeof raw === 'object' ? { ...raw } : {};
}

export function getConfiguration(): SnitchLintConfiguration {
  const config = vscode.workspace.getConfiguration(SECTION);
  const enabled = config.get<boolean>('enabled', true);
  const debounceMs = config.get<number>('debounceMs', 400);
  const logLevel = config.get<SnitchLintConfiguration['logLevel']>('logLevel', 'warn');
  const ruleOverrides = readRuleOverrides(config);

  return {
    enabled,
    debounceMs: Math.max(50, debounceMs),
    logLevel,
    ruleOverrides,
    isRuleEnabled(ruleId: string): boolean {
      if (!enabled) {
        return false;
      }
      const v = ruleOverrides[ruleId];
      return v !== false;
    },
  };
}
