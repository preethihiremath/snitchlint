import * as vscode from 'vscode';

export type LogLevel = 'off' | 'error' | 'warn' | 'info' | 'debug';

/** Higher = more verbose; message is shown if its rank is <= configured rank. */
const RANK: Record<Exclude<LogLevel, 'off'>, number> = {
  error: 0,
  warn: 1,
  info: 2,
  debug: 3,
};

export class SnitchLintLogger {
  private readonly channel: vscode.OutputChannel;
  private level: LogLevel = 'warn';

  constructor(channelName = 'SnitchLint') {
    this.channel = vscode.window.createOutputChannel(channelName);
  }

  get outputChannel(): vscode.OutputChannel {
    return this.channel;
  }

  setLevel(level: LogLevel): void {
    this.level = level;
  }

  private shouldLog(at: Exclude<LogLevel, 'off'>): boolean {
    if (this.level === 'off') {
      return false;
    }
    const configured = RANK[this.level as keyof typeof RANK] ?? 1;
    return RANK[at] <= configured;
  }

  error(message: string, err?: unknown): void {
    if (!this.shouldLog('error')) {
      return;
    }
    const suffix = err !== undefined ? `: ${String(err instanceof Error ? err.message : err)}` : '';
    this.channel.appendLine(`[error] ${message}${suffix}`);
  }

  warn(message: string): void {
    if (!this.shouldLog('warn')) {
      return;
    }
    this.channel.appendLine(`[warn] ${message}`);
  }

  info(message: string): void {
    if (!this.shouldLog('info')) {
      return;
    }
    this.channel.appendLine(`[info] ${message}`);
  }

  debug(message: string): void {
    if (!this.shouldLog('debug')) {
      return;
    }
    this.channel.appendLine(`[debug] ${message}`);
  }

  dispose(): void {
    this.channel.dispose();
  }
}
