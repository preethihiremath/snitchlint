/**
 * Static security metadata per rule: CWE, vulnerability type, rationale, risky patterns.
 * Single source of truth for AI explanations when rules do not set fields explicitly.
 */
import type { OwaspCategory } from '../types';

export interface RuleSecurityMetadata {
  readonly vulnerabilityType: string;
  readonly cweId: string;
  readonly cweName: string;
  readonly whyItMatters: string;
  readonly riskyPatterns: readonly string[];
  readonly defaultSinkLabel: string;
}

export const RULE_SECURITY_METADATA: Readonly<Record<string, RuleSecurityMetadata>> = {
  'sql-injection': {
    vulnerabilityType: 'SQL Injection',
    cweId: 'CWE-89',
    cweName: 'Improper Neutralization of Special Elements used in an SQL Command',
    whyItMatters:
      'User-controlled input is concatenated or interpolated into SQL. An attacker can alter the query structure (UNION, OR 1=1, stacked queries) and read, modify, or delete database rows.',
    riskyPatterns: ['string concatenation in SQL', 'template literals in query()', 'db.raw() with user input'],
    defaultSinkLabel: 'SQL driver query/execute',
  },
  xss: {
    vulnerabilityType: 'Cross-Site Scripting (XSS)',
    cweId: 'CWE-79',
    cweName: 'Improper Neutralization of Input During Web Page Generation',
    whyItMatters:
      'Untrusted data is written into the DOM as HTML. Browsers execute attacker-supplied scripts in the victim’s session, enabling session theft, defacement, or phishing.',
    riskyPatterns: ['element.innerHTML =', 'document.write('],
    defaultSinkLabel: 'DOM HTML sink',
  },
  'react-dangerously-set-inner-html': {
    vulnerabilityType: 'Cross-Site Scripting (XSS)',
    cweId: 'CWE-79',
    cweName: 'Improper Neutralization of Input During Web Page Generation',
    whyItMatters:
      'React’s dangerouslySetInnerHTML bypasses automatic escaping. Any unsanitized HTML in __html is rendered and can execute scripts in the user’s browser.',
    riskyPatterns: ['dangerouslySetInnerHTML'],
    defaultSinkLabel: 'dangerouslySetInnerHTML',
  },
  'hardcoded-secrets': {
    vulnerabilityType: 'Hardcoded Credentials',
    cweId: 'CWE-798',
    cweName: 'Use of Hard-coded Credentials',
    whyItMatters:
      'Secrets in source code are exposed in version control, builds, and decompilation. Anyone with repo access can impersonate services or decrypt protected data.',
    riskyPatterns: ['API keys in string literals', 'password = "..."', 'sk_live_ tokens'],
    defaultSinkLabel: 'hardcoded secret literal',
  },
  'command-injection': {
    vulnerabilityType: 'OS Command Injection',
    cweId: 'CWE-78',
    cweName: 'Improper Neutralization of Special Elements used in an OS Command',
    whyItMatters:
      'User input reaches a shell or process launcher. Attackers inject command separators (;, |, &&) to run arbitrary OS commands on the server.',
    riskyPatterns: ['child_process.exec', 'execSync with user input', 'spawn with shell:true and tainted args'],
    defaultSinkLabel: 'child_process exec/spawn',
  },
  'insecure-eval-function': {
    vulnerabilityType: 'Code Injection',
    cweId: 'CWE-94',
    cweName: 'Improper Control of Generation of Code',
    whyItMatters:
      'eval and Function() compile and run arbitrary JavaScript. Attacker-controlled strings become executable code with full process privileges.',
    riskyPatterns: ['eval(', 'new Function('],
    defaultSinkLabel: 'eval / Function constructor',
  },
  'insecure-deserialization': {
    vulnerabilityType: 'Insecure Deserialization',
    cweId: 'CWE-502',
    cweName: 'Deserialization of Untrusted Data',
    whyItMatters:
      'Parsing untrusted JSON or objects without validation can enable prototype pollution, type confusion, or logic bypass when deserialized data drives security checks.',
    riskyPatterns: ['JSON.parse on request body', 'unvalidated object revival'],
    defaultSinkLabel: 'JSON.parse / deserialize',
  },
  'weak-crypto': {
    vulnerabilityType: 'Weak Cryptographic Hash',
    cweId: 'CWE-328',
    cweName: 'Use of Weak Hash',
    whyItMatters:
      'MD5 and SHA-1 are collision-prone and unsuitable for passwords or integrity of sensitive data. Attackers can find collisions or brute-force faster than with modern algorithms.',
    riskyPatterns: ['createHash("md5")', 'createHash("sha1")'],
    defaultSinkLabel: 'crypto.createHash(md5|sha1)',
  },
  'unrestricted-file-upload': {
    vulnerabilityType: 'Unrestricted File Upload',
    cweId: 'CWE-434',
    cweName: 'Unrestricted Upload of File with Dangerous Type',
    whyItMatters:
      'Accepting uploads without type, size, and storage controls allows malware hosting, path abuse, or remote code execution if files are served or executed.',
    riskyPatterns: ['multer.single without validation', 'missing file type allowlist'],
    defaultSinkLabel: 'file upload middleware',
  },
  'insecure-cookie-flags': {
    vulnerabilityType: 'Sensitive Cookie Without Security Flags',
    cweId: 'CWE-614',
    cweName: 'Sensitive Cookie in HTTPS Session Without Secure Attribute',
    whyItMatters:
      'Cookies without HttpOnly can be read by XSS; without Secure they may leak over HTTP. Session tokens become easier to steal or replay.',
    riskyPatterns: ['res.cookie without httpOnly', 'res.cookie without secure'],
    defaultSinkLabel: 'res.cookie',
  },
  'csrf-protection': {
    vulnerabilityType: 'Cross-Site Request Forgery (CSRF)',
    cweId: 'CWE-352',
    cweName: 'Cross-Site Request Forgery (CSRF)',
    whyItMatters:
      'State-changing endpoints without anti-CSRF tokens allow malicious sites to submit requests using the victim’s browser cookies and session.',
    riskyPatterns: ['POST handlers without CSRF middleware', 'cookie-only session auth'],
    defaultSinkLabel: 'state-changing route without CSRF',
  },
  'open-redirect': {
    vulnerabilityType: 'Open Redirect',
    cweId: 'CWE-601',
    cweName: 'URL Redirection to Untrusted Site',
    whyItMatters:
      'Redirecting to user-controlled URLs enables phishing: victims trust your domain in the link but land on an attacker site that steals credentials.',
    riskyPatterns: ['res.redirect(userInput)', 'Location header from query param'],
    defaultSinkLabel: 'res.redirect',
  },
  'path-traversal': {
    vulnerabilityType: 'Path Traversal',
    cweId: 'CWE-22',
    cweName: 'Improper Limitation of a Pathname to a Restricted Directory',
    whyItMatters:
      'User input in file paths can include ../ sequences to read or write files outside the intended directory (e.g. /etc/passwd, application secrets).',
    riskyPatterns: ['fs.readFile with tainted path', 'path.join without normalization check'],
    defaultSinkLabel: 'filesystem read/write',
  },
  ssrf: {
    vulnerabilityType: 'Server-Side Request Forgery (SSRF)',
    cweId: 'CWE-918',
    cweName: 'Server-Side Request Forgery (SSRF)',
    whyItMatters:
      'The server fetches a URL controlled by the attacker, reaching internal services (metadata APIs, admin panels) or cloud credential endpoints not exposed to the internet.',
    riskyPatterns: ['fetch(userUrl)', 'http.get with tainted URL'],
    defaultSinkLabel: 'HTTP client (fetch/request)',
  },
  'jwt-weak-secret': {
    vulnerabilityType: 'Weak JWT Signing Key',
    cweId: 'CWE-347',
    cweName: 'Improper Verification of Cryptographic Signature',
    whyItMatters:
      'Signing JWTs with a short or hardcoded secret lets attackers forge tokens, escalate privileges, or impersonate users after offline brute-force.',
    riskyPatterns: ['jwt.sign with string literal secret', 'symmetric key in source'],
    defaultSinkLabel: 'jwt.sign',
  },
  'sensitive-logging': {
    vulnerabilityType: 'Insertion of Sensitive Information into Log File',
    cweId: 'CWE-532',
    cweName: 'Insertion of Sensitive Information into Log File',
    whyItMatters:
      'Passwords, tokens, and PII in logs are retained in aggregators and backups. Anyone with log access can harvest credentials for replay attacks.',
    riskyPatterns: ['console.log(password)', 'logger.info with token fields'],
    defaultSinkLabel: 'logging call',
  },
};

export function getRuleMetadata(ruleId: string): RuleSecurityMetadata | undefined {
  return RULE_SECURITY_METADATA[ruleId];
}

export function getOwaspShortLabel(owasp: OwaspCategory | undefined): string {
  if (!owasp) return '—';
  const m = owasp.match(/^(A\d{2}):\d{4}-(.+)$/);
  if (!m) return owasp;
  return `${m[1]} — ${m[2]}`;
}
