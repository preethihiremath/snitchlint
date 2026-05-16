/**
 * Webview panel for AI security insight: explanation, taint flow, CWE/OWASP, before/after fix.
 * Communicates with extension via postMessage (applyFix).
 */
import * as vscode from 'vscode';
import type { Finding } from '../types';
import { buildExplanation, type SecurityExplanation } from '../ai/explanationBuilder';
import { buildFixSuggestion, type FixSuggestion } from '../ai/fixSuggestionBuilder';
import {
  buildEnhancePrompt,
  enhanceExplanation,
  type AiEnhanceOptions,
  type LmEnhancer,
} from '../ai/optionalAiClient';

function createVsCodeLmEnhancer(enabled: boolean): LmEnhancer | undefined {
  if (!enabled || !('lm' in vscode)) {
    return undefined;
  }
  return async (prompt: string) => {
    try {
      const lm = (vscode as typeof vscode & { lm: typeof import('vscode').lm }).lm;
      const models = await lm.selectChatModels({});
      const model = models[0];
      if (!model) return undefined;
      const cts = new vscode.CancellationTokenSource();
      const response = await model.sendRequest(
        [vscode.LanguageModelChatMessage.User(prompt)],
        {},
        cts.token
      );
      let text = '';
      for await (const chunk of response.text) {
        text += chunk;
      }
      const trimmed = text.trim();
      return trimmed.length > 20 ? trimmed : undefined;
    } catch {
      return undefined;
    }
  };
}

export interface AiInsightPayload {
  readonly explanation: SecurityExplanation;
  readonly fix: FixSuggestion;
  readonly enhancedWhy?: string;
  readonly aiProvider?: string;
  readonly fileName: string;
  readonly line: number;
  readonly findingStart: number;
  readonly findingEnd: number;
}

export class AiInsightPanel {
  public static readonly viewType = 'snitchlint.aiInsight';

  private static currentPanel: AiInsightPanel | undefined;

  private readonly panel: vscode.WebviewPanel;
  private payload: AiInsightPayload | undefined;

  private constructor(
    panel: vscode.WebviewPanel,
    private readonly extensionUri: vscode.Uri,
    private readonly onApplyFix: (payload: AiInsightPayload) => Promise<void>
  ) {
    this.panel = panel;
    this.panel.onDidDispose(() => {
      AiInsightPanel.currentPanel = undefined;
    });
    this.panel.webview.onDidReceiveMessage(async (msg) => {
      if (msg.type === 'applyFix' && this.payload) {
        await this.onApplyFix(this.payload);
      }
    });
  }

  public static async show(
    context: vscode.ExtensionContext,
    document: vscode.TextDocument,
    finding: Finding,
    aiOptions: AiEnhanceOptions,
    onApplyFix: (payload: AiInsightPayload) => Promise<void>
  ): Promise<void> {
    const explanation = buildExplanation(finding);
    const fix = buildFixSuggestion(finding, document.getText());

    let enhancedWhy: string | undefined;
    let aiProvider: string | undefined;

    const lmEnhancer = createVsCodeLmEnhancer(aiOptions.useVsCodeLm);
    if (aiOptions.ollamaEnabled || lmEnhancer) {
      const prompt = buildEnhancePrompt(explanation);
      const enhanced = await enhanceExplanation(prompt, aiOptions, lmEnhancer);
      enhancedWhy = enhanced.enhancedWhy;
      aiProvider = enhanced.provider;
    }

    const position = document.positionAt(finding.start);
    const payload: AiInsightPayload = {
      explanation,
      fix,
      enhancedWhy,
      aiProvider: aiProvider && aiProvider !== 'none' ? aiProvider : undefined,
      fileName: document.fileName,
      line: position.line + 1,
      findingStart: finding.start,
      findingEnd: finding.end,
    };

    if (AiInsightPanel.currentPanel) {
      AiInsightPanel.currentPanel.panel.reveal(vscode.ViewColumn.Beside);
      AiInsightPanel.currentPanel.update(payload);
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      AiInsightPanel.viewType,
      'SnitchLint AI Insight',
      vscode.ViewColumn.Beside,
      { enableScripts: true, retainContextWhenHidden: true }
    );

    AiInsightPanel.currentPanel = new AiInsightPanel(panel, context.extensionUri, onApplyFix);
    AiInsightPanel.currentPanel.update(payload);
  }

  private update(payload: AiInsightPayload): void {
    this.payload = payload;
    this.panel.webview.html = renderHtml(payload, this.panel.webview);
    this.panel.title = `SnitchLint — ${payload.explanation.vulnerabilityType}`;
  }
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderTaintFlow(explanation: SecurityExplanation): string {
  if (explanation.taintFlow.length === 0) {
    return '<p class="muted">No structured flow recorded — see summary above.</p>';
  }
  return explanation.taintFlow
    .map((step) => {
      const badge = step.kind.toUpperCase();
      const code = step.code ? `<code>${escapeHtml(step.code)}</code>` : '';
      return `<div class="step step-${escapeHtml(step.kind)}">
        <span class="badge">${badge}</span>
        <span>${escapeHtml(step.label)}</span>
        ${code}
      </div>`;
    })
    .join('<div class="arrow">↓</div>');
}

function renderHtml(payload: AiInsightPayload, webview: vscode.Webview): string {
  const { explanation, fix, enhancedWhy, aiProvider } = payload;
  const cspSource = webview.cspSource;
  const why = enhancedWhy ?? explanation.whyVulnerable;
  const aiNote = aiProvider
    ? `<p class="ai-note">Enhanced with ${escapeHtml(aiProvider)} (optional local/cloud model)</p>`
    : '<p class="ai-note">Analysis powered by SnitchLint static analysis (offline, no API key)</p>';

  const patterns =
    explanation.riskyPatterns.length > 0
      ? `<ul>${explanation.riskyPatterns.map((p) => `<li><code>${escapeHtml(p)}</code></li>`).join('')}</ul>`
      : '';

  const applyBtn = fix.canApply
    ? '<button class="primary" id="applyFix">Apply fix to editor</button>'
    : '<button class="secondary" disabled title="Replace manually using the suggested pattern">Apply not available — use snippet below</button>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${cspSource} 'unsafe-inline'; script-src ${cspSource};" />
  <style>
    :root {
      --bg: var(--vscode-editor-background);
      --fg: var(--vscode-editor-foreground);
      --muted: var(--vscode-descriptionForeground);
      --border: var(--vscode-panel-border, #444);
      --accent: var(--vscode-textLink-foreground, #3794ff);
      --danger: var(--vscode-errorForeground, #f14c4c);
      --code-bg: var(--vscode-textCodeBlock-background, #2d2d2d);
    }
    body { font-family: var(--vscode-font-family); font-size: 13px; color: var(--fg); background: var(--bg); margin: 0; padding: 16px 20px 32px; line-height: 1.5; }
    h1 { font-size: 18px; margin: 0 0 4px; }
    h2 { font-size: 14px; margin: 20px 0 8px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }
    .tag { display: inline-block; background: var(--code-bg); padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-right: 6px; }
    .summary { border-left: 3px solid var(--danger); padding: 8px 12px; margin: 12px 0; background: var(--code-bg); }
    .step { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; padding: 10px 12px; border: 1px solid var(--border); border-radius: 6px; margin: 6px 0; }
    .step-source .badge { background: #2d6a4f; }
    .step-propagation .badge { background: #6a5acd; }
    .step-sink .badge { background: #9d0208; }
    .badge { font-size: 10px; font-weight: 600; padding: 2px 6px; border-radius: 3px; color: #fff; }
    .arrow { text-align: center; color: var(--muted); font-size: 12px; }
    .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px 16px; }
    .meta-item label { display: block; font-size: 11px; color: var(--muted); }
    pre { background: var(--code-bg); padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; margin: 8px 0; white-space: pre-wrap; word-break: break-word; }
    pre.before { border-left: 3px solid var(--danger); }
    pre.after { border-left: 3px solid #2d6a4f; }
    .compare { display: grid; gap: 12px; }
    @media (min-width: 640px) { .compare { grid-template-columns: 1fr 1fr; } }
    button { margin-top: 12px; padding: 8px 14px; border: none; border-radius: 4px; cursor: pointer; font-size: 13px; }
    .primary { background: var(--accent); color: #fff; }
    .secondary { background: var(--code-bg); color: var(--muted); cursor: not-allowed; }
    .muted { color: var(--muted); font-size: 12px; }
    .ai-note { font-size: 11px; color: var(--muted); margin-top: 16px; }
    code { font-family: var(--vscode-editor-font-family); font-size: 12px; }
  </style>
</head>
<body>
  <h1>${escapeHtml(explanation.vulnerabilityType)}</h1>
  <p class="muted">${escapeHtml(payload.fileName)} · line ${payload.line} · rule <code>${escapeHtml(explanation.ruleId)}</code></p>

  <div class="summary">${escapeHtml(explanation.summary)}</div>

  <h2>Why this is vulnerable</h2>
  <p>${escapeHtml(why)}</p>
  ${aiNote}

  <h2>Taint flow</h2>
  ${renderTaintFlow(explanation)}

  <h2>Classification</h2>
  <div class="meta-grid">
    <div class="meta-item"><label>OWASP Top 10</label><span class="tag">${escapeHtml(explanation.owasp)}</span></div>
    <div class="meta-item"><label>CWE</label><span class="tag">${escapeHtml(explanation.cweId)}</span></div>
    <div class="meta-item" style="grid-column: 1 / -1"><label>CWE name</label>${escapeHtml(explanation.cweName)}</div>
    <div class="meta-item" style="grid-column: 1 / -1"><label>Risky API / pattern</label><code>${escapeHtml(explanation.riskyApi)}</code></div>
  </div>
  ${patterns ? `<h2>Known risky patterns</h2>${patterns}` : ''}

  <h2>Secure fix (before / after)</h2>
  <p class="muted">${escapeHtml(fix.rationale)}</p>
  <div class="compare">
    <div><strong>Before</strong><pre class="before">${escapeHtml(fix.before)}</pre></div>
    <div><strong>After</strong><pre class="after">${escapeHtml(fix.after)}</pre></div>
  </div>
  ${applyBtn}

  <script>
    const vscode = acquireVsCodeApi();
    const btn = document.getElementById('applyFix');
    if (btn) btn.addEventListener('click', () => vscode.postMessage({ type: 'applyFix' }));
  </script>
</body>
</html>`;
}
