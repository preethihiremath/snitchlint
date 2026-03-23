import * as ts from 'typescript';
import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from './ruleTypes';

/**
 * Pattern-based complement: React dangerouslySetInnerHTML with obvious dynamic content.
 */
export const reactXssRule: SecurityRule = {
  id: 'react-dangerously-set-inner-html',
  title: 'React dangerouslySetInnerHTML',
  owasp: 'A03:2021-Injection',
  description: 'Detects dangerouslySetInnerHTML in JSX/object literals.',
  analyze(ctx: RuleContext): readonly Finding[] {
    const out: Finding[] = [];
    const text = ctx.fullText;
    const re = /dangerouslySetInnerHTML\s*:/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const start = m.index;
      const end = Math.min(text.length, start + 80);
      out.push({
        ruleId: 'react-dangerously-set-inner-html',
        severity: 'warning',
        message: 'dangerouslySetInnerHTML can introduce XSS if __html is not sanitized.',
        suggestion: 'Use a vetted sanitizer (e.g. DOMPurify) or avoid raw HTML.',
        start,
        end,
        owasp: 'A03:2021-Injection',
      });
    }
    return out;
  },
};
