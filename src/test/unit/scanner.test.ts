import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { scanDocument } from '../../engine/scanner';
import { allSecurityRules } from '../../rules/registry';
import { createTestConfiguration } from '../../config/configuration';

function readFixture(name: string): string {
  const p = path.join(process.cwd(), 'src', 'test', 'fixtures', name);
  return fs.readFileSync(p, 'utf-8');
}

describe('scanDocument (unit)', () => {
  const config = createTestConfiguration({ logLevel: 'off' });

  it('detects multiple OWASP-style issues in consolidated fixture', () => {
    const text = readFixture('owasp-top10-samples.ts');
    const { findings } = scanDocument(
      { fileName: 'owasp-top10-samples.ts', text, languageId: 'typescript' },
      allSecurityRules,
      config,
      () => {
        /* noop */
      }
    );

    const ids = new Set(findings.map((f) => f.ruleId));
    assert.ok(ids.has('sql-injection'), 'expected sql-injection');
    assert.ok(ids.has('xss'), 'expected xss');
    assert.ok(ids.has('command-injection'), 'expected command-injection');
    assert.ok(ids.has('insecure-eval-function'), 'expected insecure-eval-function');
    assert.ok(ids.has('weak-crypto'), 'expected weak-crypto');
    assert.ok(ids.has('hardcoded-secrets'), 'expected hardcoded-secrets');
    assert.ok(ids.has('jwt-weak-secret'), 'expected jwt-weak-secret');
    assert.ok(ids.has('insecure-deserialization'), 'expected insecure-deserialization');
    assert.ok(ids.has('sensitive-logging'), 'expected sensitive-logging');
    assert.ok(ids.has('ssrf'), 'expected ssrf');
    assert.ok(ids.has('path-traversal'), 'expected path-traversal');
    assert.ok(ids.has('react-dangerously-set-inner-html'), 'expected react rule');
    assert.ok(ids.has('unrestricted-file-upload'), 'expected file upload heuristic');
    assert.ok(ids.has('insecure-cookie-flags'), 'expected cookie flags');
    assert.ok(ids.has('open-redirect'), 'expected open redirect');
  });

  it('respects disabled rules', () => {
    const text = readFixture('owasp-top10-samples.ts');
    const disabledSql = createTestConfiguration({
      logLevel: 'off',
      ruleOverrides: { 'sql-injection': false },
    });
    const { findings } = scanDocument(
      { fileName: 'x.ts', text, languageId: 'typescript' },
      allSecurityRules,
      disabledSql,
      () => {
        /* noop */
      }
    );
    assert.ok(!findings.some((f) => f.ruleId === 'sql-injection'));
  });

  it('returns empty for unsupported language', () => {
    const { findings } = scanDocument(
      { fileName: 'x.py', text: 'print(1)', languageId: 'python' },
      allSecurityRules,
      config,
      () => {
        /* noop */
      }
    );
    assert.strictEqual(findings.length, 0);
  });
});
