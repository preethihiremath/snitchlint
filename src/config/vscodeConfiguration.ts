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

  const ollamaEnabled = config.get<boolean>('ai.ollamaEnabled', false);
  const ollamaUrl = config.get<string>('ai.ollamaUrl', 'http://127.0.0.1:11434');
  const ollamaModel = config.get<string>('ai.ollamaModel', 'llama3.2');
  const useVsCodeLm = config.get<boolean>('ai.useVsCodeLm', false);

  return {
    enabled,
    debounceMs: Math.max(50, debounceMs),
    logLevel,
    ruleOverrides,
    ai: {
      ollamaEnabled,
      ollamaUrl,
      ollamaModel,
      useVsCodeLm,
    },
    isRuleEnabled(ruleId: string): boolean {
      if (!enabled) {
        return false;
      }
      const v = ruleOverrides[ruleId];
      return v !== false;
    },
  };
}
