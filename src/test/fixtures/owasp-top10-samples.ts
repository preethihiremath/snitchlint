/**
 * Intentionally vulnerable patterns for SnitchLint tests and manual QA.
 * OWASP Top 10 (2021) coverage samples — do not use in production.
 * Kept free of external type dependencies so `tsc --noEmit` passes in this repo.
 */

// Minimal stand-ins (avoid importing real frameworks in fixtures)
const jwt = {
  sign: (_payload: object, _secret: string): string => '',
};

const multer = (): { single: (field: string) => unknown } => ({
  single: (_field: string) => ({}),
});

// Minimal stubs to avoid relying on Node/browser type libs in the editor/tsconfig.
// These must keep stable identifier names so the AST-based rules can match them.
declare const fetch: any;
declare const console: { log: (...args: unknown[]) => void; warn?: (...args: unknown[]) => void; info?: (...args: unknown[]) => void; debug?: (...args: unknown[]) => void };
declare const createHash: any;
declare const exec: any;

const fs = {
  readFileSync: (_path: string): string => '',
};

// A01 — Broken access control (open redirect)
export function redirectBad(res: { redirect: (u: string) => void }, req: { query: { next: string } }) {
  res.redirect(req.query.next);
}

// A02 — Cryptographic failures (weak hash + hardcoded secret)
const STRIPE_LIVE = 'sk_live_1234567890ABCDEF1234';

export function weakHash(data: string) {
  return createHash('md5').update(data).digest('hex');
}



// A03 — Injection (SQL + XSS + command + eval)
export function sqlSink(db: { query: (s: string) => void }, req: { body: { id: string } }) {
  const userId = req.body.id;
  const q = `SELECT * FROM u WHERE id = '${userId}'`;
  db.query(q);
}

export function xssSink(div: { innerHTML: string }, req: { body: { html: string } }) {
  div.innerHTML = req.body.html;
}

export function cmdSink(req: { query: { cmd: string } }) {
  exec(req.query.cmd);
}

export function evalSink(req: { body: { code: string } }) {
  eval(req.body.code);
}

// A04 — Insecure design (upload)
const upload = multer();
export const uploadSingle = upload.single('file');

// A05 — Misconfiguration (cookies)
export function cookieBad(res: { cookie: (name: string, val: string, opts?: object) => void }) {
  res.cookie('session', 'abc', { path: '/' });
}

// A07 — Identification failures (JWT hardcoded secret)
export function signToken(payload: object) {
  return jwt.sign(payload, 'super-secret-string');
}

// A08 — Integrity failures (insecure deserialization)
export function parseBody(req: { body: string }) {
  return JSON.parse(req.body);
}

// A09 — Logging failures (sensitive logging)
export function logUser(password: string) {
  console.log('password=' + password);
}

// A10 — SSRF
export async function ssrf(req: { query: { url: string } }) {
  return fetch(req.query.url);
}

// Path traversal
export function readUserPath(req: { params: { p: string } }) {
  return fs.readFileSync(req.params.p);
}

// React XSS pattern (string scan)
export const reactSnippet = { props: { dangerouslySetInnerHTML: { __html: '<b>x</b>' } } };

void uploadSingle;
void reactSnippet;
