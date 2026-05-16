/**
 * Optional AI enhancement — never required for the extension to work.
 *
 * - Ollama: free local models at http://127.0.0.1:11434 (opt-in via snitchlint.ai.ollamaEnabled)
 * - VS Code LM: Copilot/other models when snitchlint.ai.useVsCodeLm is true
 *
 * Default explanations come from explanationBuilder (static analysis only).
 */

export interface AiEnhanceOptions {
  readonly ollamaEnabled: boolean;
  readonly ollamaUrl: string;
  readonly ollamaModel: string;
  readonly useVsCodeLm: boolean;
}

export interface AiEnhanceResult {
  readonly enhancedWhy?: string;
  readonly provider?: 'ollama' | 'vscode-lm' | 'none';
}

const OLLAMA_TIMEOUT_MS = 30_000;

export type LmEnhancer = (prompt: string) => Promise<string | undefined>;

export async function enhanceExplanation(
  prompt: string,
  options: AiEnhanceOptions,
  vscodeLmEnhance?: LmEnhancer
): Promise<AiEnhanceResult> {
  if (options.ollamaEnabled) {
    const result = await tryOllama(prompt, options.ollamaUrl, options.ollamaModel);
    if (result) {
      return { enhancedWhy: result, provider: 'ollama' };
    }
  }

  if (options.useVsCodeLm && vscodeLmEnhance) {
    const result = await vscodeLmEnhance(prompt);
    if (result) {
      return { enhancedWhy: result, provider: 'vscode-lm' };
    }
  }

  return { provider: 'none' };
}

async function tryOllama(prompt: string, baseUrl: string, model: string): Promise<string | undefined> {
  const url = `${baseUrl.replace(/\/$/, '')}/api/generate`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), OLLAMA_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        prompt,
        stream: false,
        options: { temperature: 0.2, num_predict: 256 },
      }),
      signal: controller.signal,
    });
    if (!res.ok) return undefined;
    const data = (await res.json()) as { response?: string };
    const text = data.response?.trim();
    return text && text.length > 20 ? text : undefined;
  } catch {
    return undefined;
  } finally {
    clearTimeout(timer);
  }
}

export function buildEnhancePrompt(explanation: {
  vulnerabilityType: string;
  whyVulnerable: string;
  taintFlow: readonly { kind: string; label: string }[];
  cweId: string;
  riskyApi: string;
}): string {
  const flow = explanation.taintFlow.map((s) => `${s.kind}: ${s.label}`).join(' → ');
  return `You are a security educator. In 2-3 short sentences, explain WHY this is vulnerable in plain language.
Vulnerability: ${explanation.vulnerabilityType} (${explanation.cweId})
Risky API: ${explanation.riskyApi}
Taint flow: ${flow}
Context: ${explanation.whyVulnerable}
Do not include code blocks. Be precise and concise.`;
}
