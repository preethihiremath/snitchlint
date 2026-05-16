import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { scanDocument } from '../../engine/scanner';
import { allSecurityRules } from '../../rules/registry';
import { createTestConfiguration } from '../../config/configuration';
import { buildExplanation } from '../../ai/explanationBuilder';
import { buildFixSuggestion } from '../../ai/fixSuggestionBuilder';
import { enrichFinding } from '../../ai/findingEnricher';

function readFixture(name: string): string {
  const p = path.join(process.cwd(), 'src', 'test', 'fixtures', name);
  return fs.readFileSync(p, 'utf-8');
}

describe('AI explanation & fix builders', () => {
  const config = createTestConfiguration({ logLevel: 'off' });

  it('enriches findings with CWE and taint flow metadata', () => {
    const text = readFixture('sql-example.ts');
    const { findings } = scanDocument(
      { fileName: 'sql-example.ts', text, languageId: 'typescript' },
      allSecurityRules,
      config,
      () => {
        /* noop */
      }
    );
    const sql = findings.find((f) => f.ruleId === 'sql-injection');
    assert.ok(sql, 'expected sql finding');
    assert.strictEqual(sql!.cweId, 'CWE-89');
    assert.ok(sql!.taintFlow && sql!.taintFlow.length >= 2);
    assert.ok(sql!.vulnerabilityType?.includes('SQL'));
  });

  it('builds explanation with OWASP and taint flow', () => {
    const text = readFixture('xss-example.ts');
    const { findings } = scanDocument(
      { fileName: 'xss-example.ts', text, languageId: 'typescript' },
      allSecurityRules,
      config,
      () => {
        /* noop */
      }
    );
    const xss = findings.find((f) => f.ruleId === 'xss');
    assert.ok(xss);
    const explanation = buildExplanation(xss!);
    assert.ok(explanation.whyVulnerable.length > 20);
    assert.strictEqual(explanation.cweId, 'CWE-79');
    assert.ok(explanation.owasp.startsWith('A03'));
    assert.ok(explanation.taintFlow.some((s) => s.kind === 'sink'));
  });

  it('suggests parameterized query fix for SQL injection', () => {
    const text = readFixture('sql-example.ts');
    const { findings } = scanDocument(
      { fileName: 'sql-example.ts', text, languageId: 'typescript' },
      allSecurityRules,
      config,
      () => {
        /* noop */
      }
    );
    const sql = findings.find((f) => f.ruleId === 'sql-injection')!;
    const fix = buildFixSuggestion(sql, text);
    assert.ok(fix.after.includes('?'));
    assert.ok(/parameter|placeholder|bind/i.test(fix.rationale));
  });

  it('enricher infers taint flow from message when missing', () => {
    const enriched = enrichFinding({
      ruleId: 'ssrf',
      severity: 'warning',
      message: 'Possible SSRF: tainted data from "req.query.url" reaches fetch.',
      start: 0,
      end: 5,
      owasp: 'A10:2021-Server-Side Request Forgery',
    });
    assert.strictEqual(enriched.cweId, 'CWE-918');
    assert.ok(enriched.taintFlow?.some((s) => s.kind === 'source'));
    assert.ok(enriched.taintFlow?.some((s) => s.kind === 'sink'));
  });
});
