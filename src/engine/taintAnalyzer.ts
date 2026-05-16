import * as ts from 'typescript';
import { TAINT_SOURCES } from '../rules/constants';

export type TaintOrigin = string;
export type TaintOrigins = Set<TaintOrigin>;

interface FunctionScope {
  readonly id: string;
  readonly name: string;
  readonly node: ts.FunctionLikeDeclarationBase;
  readonly paramNames: readonly string[];
  readonly start: number;
  readonly end: number;
  readonly constraints: readonly TaintConstraint[];
}

interface TaintConstraint {
  /**
   * Identifier names to taint when `expr` taints.
   * (We taint identifiers, not deep property paths.)
   */
  readonly targets: readonly string[];
  readonly expr: ts.Expression;
}

interface CallSite {
  readonly calledFunctionName: string;
  readonly scopeId: string;
  readonly callNode: ts.CallExpression;
}

export interface TaintAnalyzerOptions {
  readonly taintSources?: readonly string[];
  /**
   * Optional sanitizer allowlist:
   * if call expression matches one of these names, its return is treated as not tainted
   * (even if arguments are tainted).
   */
  readonly sanitizerNames?: readonly string[];
}

function unionInto(target: TaintOrigins, src: TaintOrigins): boolean {
  let changed = false;
  for (const o of src) {
    if (!target.has(o)) {
      target.add(o);
      changed = true;
    }
  }
  return changed;
}

function emptySet(): TaintOrigins {
  return new Set<TaintOrigin>();
}

function mergeSets(a: TaintOrigins, b: TaintOrigins): TaintOrigins {
  const out = new Set<TaintOrigin>(a);
  for (const x of b) out.add(x);
  return out;
}

function getBindingIdentifiersFromName(name: ts.BindingName): readonly string[] {
  if (ts.isIdentifier(name)) {
    return [name.text];
  }
  if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
    const out: string[] = [];
    for (const el of name.elements) {
      if (ts.isBindingElement(el)) {
        if (ts.isIdentifier(el.name)) {
          out.push(el.name.text);
        } else {
          out.push(...getBindingIdentifiersFromName(el.name as ts.BindingName));
        }
      }
    }
    return out;
  }
  return [];
}

function getAssignmentTargets(left: ts.LeftHandSideExpression): readonly string[] {
  if (ts.isIdentifier(left)) {
    return [left.text];
  }
  if (ts.isPropertyAccessExpression(left)) {
    // Example: `obj.prop = rhs` -> taint `obj` so later `obj.prop` is treated tainted.
    if (ts.isIdentifier(left.expression)) {
      return [left.expression.text];
    }
  }
  if (ts.isElementAccessExpression(left)) {
    if (ts.isIdentifier(left.expression)) {
      return [left.expression.text];
    }
  }
  return [];
}

/**
 * Lightweight monotonic taint analysis:
 * - expression taint evaluation is origin-tracking (Set<string>)
 * - assignments add taint, never remove it
 * - call return is treated as tainted if arguments are tainted (conservative)
 * - parameters are seeded from tainted call sites to catch sinks inside helpers
 *
 * This is not a full-blown compiler dataflow, but it is substantially more than
 * pattern/regex checks and removes many false negatives in taint-sensitive rules.
 */
export class TaintAnalyzer {
  private readonly taintSources: readonly string[];
  private readonly sanitizerNames: ReadonlySet<string>;

  private readonly sourceFile: ts.SourceFile;

  private readonly functionScopes: readonly FunctionScope[];
  private readonly topConstraints: readonly TaintConstraint[];
  private readonly callSites: readonly CallSite[];

  /**
   * Map: scopeId -> identifier -> taint origins
   * (Monotonic: once tainted, stays tainted.)
   */
  private readonly taintEnv: Map<string, Map<string, TaintOrigins>>;

  constructor(
    sourceFile: ts.SourceFile,
    options?: TaintAnalyzerOptions
  ) {
    this.sourceFile = sourceFile;
    this.taintSources = options?.taintSources ?? TAINT_SOURCES;
    this.sanitizerNames = new Set<string>((options?.sanitizerNames ?? []).map((s) => s.toLowerCase()));

    const fnTable = this.collectFunctionScopes();
    this.functionScopes = fnTable.functionScopes;
    this.topConstraints = fnTable.topConstraints;
    this.callSites = fnTable.callSites;

    this.taintEnv = new Map();
    for (const fn of this.functionScopes) {
      this.taintEnv.set(fn.id, new Map());
    }
    this.taintEnv.set('top', new Map());

    // Seed parameters based on call sites + iterative fixpoint.
    // We do a small bounded iteration since taint grows monotonically.
    this.runFixpoint(6);
  }

  /**
   * Return taint origins for an expression at its best-effort enclosing scope.
   */
  getTaintOrigins(expr: ts.Expression): TaintOrigins {
    const scopeId = this.getEnclosingScopeId(expr);
    return this.getTaintOriginsInScope(expr, scopeId);
  }

  private getTaintOriginsInScope(expr: ts.Expression, scopeId: string): TaintOrigins {
    const exprText = expr.getText(this.sourceFile);
    if (this.isDirectTaintSourceText(exprText)) {
      // Return the first matching source string for nicer UI messages.
      for (const s of this.taintSources) {
        if (exprText.includes(s)) return new Set([s]);
      }
    }

    if (ts.isIdentifier(expr)) {
      const env = this.taintEnv.get(scopeId);
      const got = env?.get(expr.text);
      return got ? new Set(got) : emptySet();
    }

    if (ts.isPropertyAccessExpression(expr)) {
      // If root is tainted, treat the full property access as tainted.
      const base = expr.expression;
      return this.getTaintOriginsInScope(base as ts.Expression, scopeId);
    }

    if (ts.isElementAccessExpression(expr)) {
      return this.getTaintOriginsInScope(expr.expression, scopeId);
    }

    if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      return mergeSets(
        this.getTaintOriginsInScope(expr.left, scopeId),
        this.getTaintOriginsInScope(expr.right, scopeId)
      );
    }

    if (ts.isTemplateExpression(expr)) {
      let out = emptySet();
      for (const span of expr.templateSpans) {
        out = mergeSets(out, this.getTaintOriginsInScope(span.expression, scopeId));
      }
      return out;
    }

    if (ts.isConditionalExpression(expr)) {
      return mergeSets(
        this.getTaintOriginsInScope(expr.whenTrue, scopeId),
        this.getTaintOriginsInScope(expr.whenFalse, scopeId)
      );
    }

    if (ts.isAsExpression(expr) || ts.isTypeAssertionExpression(expr) || ts.isNonNullExpression(expr) || ts.isParenthesizedExpression(expr)) {
      const inner = (expr as unknown as { expression: ts.Expression }).expression;
      return this.getTaintOriginsInScope(inner, scopeId);
    }

    if (ts.isCallExpression(expr)) {
      const fnText = expr.expression.getText(this.sourceFile).toLowerCase();
      const calleeId = ts.isIdentifier(expr.expression) ? expr.expression.text.toLowerCase() : '';
      const isSanitizer =
        (calleeId && this.sanitizerNames.has(calleeId)) ||
        this.sanitizerNames.has(fnText);
      if (isSanitizer) {
        return emptySet();
      }

      let out = emptySet();
      for (const arg of expr.arguments) {
        out = mergeSets(out, this.getTaintOriginsInScope(arg, scopeId));
      }
      return out;
    }

    return emptySet();
  }

  private isDirectTaintSourceText(exprText: string): boolean {
    return this.taintSources.some((s) => exprText.includes(s));
  }

  private getEnclosingScopeId(node: ts.Node): string {
    const off = node.getStart(this.sourceFile);
    let best: { id: string; size: number } | undefined;

    for (const fn of this.functionScopes) {
      if (off >= fn.start && off <= fn.end) {
        const size = fn.end - fn.start;
        if (!best || size < best.size) {
          best = { id: fn.id, size };
        }
      }
    }
    return best?.id ?? 'top';
  }

  private ensureEnv(scopeId: string): Map<string, TaintOrigins> {
    const existing = this.taintEnv.get(scopeId);
    if (existing) return existing;
    const m = new Map<string, TaintOrigins>();
    this.taintEnv.set(scopeId, m);
    return m;
  }

  private addOrigins(scopeId: string, identifier: string, origins: TaintOrigins): boolean {
    if (origins.size === 0) return false;
    const env = this.ensureEnv(scopeId);
    const cur = env.get(identifier);
    if (!cur) {
      env.set(identifier, new Set(origins));
      return true;
    }
    return unionInto(cur, origins);
  }

  private runFixpoint(maxIterations: number): void {
    // Function parameter seeding happens by scanning call sites.
    // We represent parameter taint as tainting the parameter identifier in the callee scope env.
    let changed = true;
    let iter = 0;

    while (changed && iter < maxIterations) {
      iter++;
      changed = false;

      // 1) apply constraints in all scopes
      for (const c of this.topConstraints) {
        const origins = this.getTaintOriginsInScope(c.expr, 'top');
        for (const t of c.targets) {
          changed = this.addOrigins('top', t, origins) || changed;
        }
      }

      for (const fn of this.functionScopes) {
        for (const c of fn.constraints) {
          const origins = this.getTaintOriginsInScope(c.expr, fn.id);
          for (const t of c.targets) {
            changed = this.addOrigins(fn.id, t, origins) || changed;
          }
        }
      }

      // 2) seed parameters from tainted call sites to catch sinks inside helpers.
      for (const call of this.callSites) {
        const calledFns = this.functionScopes.filter((f) => f.name === call.calledFunctionName);
        if (calledFns.length === 0) continue;

        // Seed by argument taint (conservative: if arg is tainted, param is tainted).
        const args = call.callNode.arguments;
        for (const fn of calledFns) {
          for (let i = 0; i < Math.min(fn.paramNames.length, args.length); i++) {
            const paramName = fn.paramNames[i];
            const argOrigins = this.getTaintOriginsInScope(args[i] as ts.Expression, call.scopeId);
            if (argOrigins.size > 0) {
              changed = this.addOrigins(fn.id, paramName, argOrigins) || changed;
            }
          }
        }
      }
    }
  }

  private collectFunctionScopes(): {
    functionScopes: FunctionScope[];
    topConstraints: TaintConstraint[];
    callSites: CallSite[];
  } {
    const functionScopes: FunctionScope[] = [];
    const topConstraints: TaintConstraint[] = [];
    const callSites: CallSite[] = [];

    const functionByName = new Map<string, ts.FunctionLikeDeclarationBase>();

    const visit = (node: ts.Node): void => {
      if (ts.isFunctionDeclaration(node) && node.name) {
        functionByName.set(node.name.text, node);
      }
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
        const init = node.initializer;
        if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) {
          const name = node.name.text;
          functionByName.set(name, init);
        }
      }
    };

    // First pass: collect function-like nodes for interprocedural seeding.
    this.walkTopLevel(this.sourceFile, (n) => visit(n));

    // Second pass: build scopes constraints.
    const scopeIdFor = (fnNode: ts.FunctionLikeDeclarationBase, idx: number): string => {
      const name = (fnNode as ts.FunctionDeclaration).name?.text
        ?? (ts.isArrowFunction(fnNode) ? '__arrow__' : '__fn__');
      return `fn:${name}:${idx}`;
    };

    let fnIndex = 0;
    for (const [fnName, fnNode] of functionByName.entries()) {
      // We only support block-bodied functions for now.
      if (!('body' in fnNode) || !fnNode.body || !ts.isBlock(fnNode.body)) continue;
      const paramNames: string[] = [];
      for (const p of fnNode.parameters) {
        if (ts.isIdentifier(p.name)) {
          paramNames.push(p.name.text);
        }
      }
      const start = fnNode.getStart(this.sourceFile);
      const end = fnNode.getEnd();

      const constraints = this.collectConstraintsInScope(fnNode.body, paramNames);
      functionScopes.push({
        id: scopeIdFor(fnNode, fnIndex),
        name: fnName,
        node: fnNode,
        paramNames,
        start,
        end,
        constraints,
      });
      fnIndex++;
    }

    // Constraints from top-level only (do not traverse into nested function bodies).
    const topConstraintsCollected = this.collectConstraintsInScope(this.sourceFile, []);
    topConstraints.push(...topConstraintsCollected);

    // Call sites from anywhere (used later to seed parameter taint).
    const getScopeIdForNode = (node: ts.Node): string => {
      const off = node.getStart(this.sourceFile);
      let best: { id: string; size: number } | undefined;
      for (const fn of functionScopes) {
        if (off >= fn.start && off <= fn.end) {
          const size = fn.end - fn.start;
          if (!best || size < best.size) {
            best = { id: fn.id, size };
          }
        }
      }
      return best?.id ?? 'top';
    };

    this.walkTopLevel(this.sourceFile, (n) => {
      if (ts.isCallExpression(n)) {
        if (ts.isIdentifier(n.expression)) {
          callSites.push({
            calledFunctionName: n.expression.text,
            scopeId: getScopeIdForNode(n),
            callNode: n,
          });
        }
      }
    });

    return { functionScopes, topConstraints, callSites };
  }

  private collectConstraintsInScope(scopeNode: ts.Node, _paramNames: readonly string[]): readonly TaintConstraint[] {
    const constraints: TaintConstraint[] = [];

    const addConstraint = (targets: readonly string[], expr: ts.Expression | undefined): void => {
      if (!expr) return;
      if (targets.length === 0) return;
      constraints.push({
        targets,
        expr,
      });
    };

    const walk = (node: ts.Node): void => {
      // Do not cross function boundaries when collecting constraints for a given scope.
      if (node !== scopeNode && (ts.isFunctionDeclaration(node) || ts.isArrowFunction(node) || ts.isFunctionExpression(node))) {
        return;
      }

      if (ts.isVariableDeclaration(node) && node.initializer) {
        const targets = getBindingIdentifiersFromName(node.name);
        addConstraint(targets, node.initializer);
        return;
      }

      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        if (ts.isExpression(node.left)) {
          const targets = getAssignmentTargets(node.left as ts.LeftHandSideExpression);
          addConstraint(targets, node.right);
        }
      }

      ts.forEachChild(node, walk);
    };

    walk(scopeNode);
    return constraints;
  }

  private walkTopLevel(node: ts.Node, cb: (n: ts.Node) => void): void {
    // Walk the tree and call cb on each node. Kept intentionally simple.
    const walk = (n: ts.Node): void => {
      cb(n);
      ts.forEachChild(n, walk);
    };
    walk(node);
  }
}

