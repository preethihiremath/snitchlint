import * as ts from 'typescript';
import type { Finding } from '../types';
import type { RuleContext, SecurityRule } from './ruleTypes';
import { TAINT_SOURCES, SQL_SINK_METHODS } from './constants';

interface TaintAnalysisContext {
  taintedVars: Set<string>;
}

function isExpressionTainted(expr: ts.Expression, taintedVarsInScope: Set<string>, sourceFile: ts.SourceFile): string | null {
  if (ts.isIdentifier(expr)) {
    return taintedVarsInScope.has(expr.text) ? expr.text : null;
  }
  if (ts.isPropertyAccessExpression(expr)) {
    let current: ts.Expression = expr;
    while (ts.isPropertyAccessExpression(current)) {
      current = current.expression;
    }
    if (ts.isIdentifier(current) && taintedVarsInScope.has(current.text)) {
      return current.text;
    }
  } else if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const leftTaint = isExpressionTainted(expr.left, taintedVarsInScope, sourceFile);
    if (leftTaint) {
      return leftTaint;
    }
    return isExpressionTainted(expr.right, taintedVarsInScope, sourceFile);
  } else if (ts.isTemplateExpression(expr)) {
    for (const span of expr.templateSpans) {
      const spanTaint = isExpressionTainted(span.expression, taintedVarsInScope, sourceFile);
      if (spanTaint) {
        return spanTaint;
      }
    }
  }
  return null;
}

function findTaintedSources(node: ts.Node, ctx: TaintAnalysisContext, sourceFile: ts.SourceFile): void {
  if (ts.isVariableDeclaration(node) && node.initializer) {
    const varNameNode = node.name;
    const initializerExpr = node.initializer;
    const initializerText = initializerExpr.getText(sourceFile);

    let shouldTaint = false;
    let taintedOriginVar: string | null = null;

    if (TAINT_SOURCES.some((source) => initializerText.startsWith(source))) {
      shouldTaint = true;
      taintedOriginVar = initializerText;
    }

    if (!shouldTaint) {
      const taintFromInitializer = isExpressionTainted(initializerExpr, ctx.taintedVars, sourceFile);
      if (taintFromInitializer) {
        shouldTaint = true;
        taintedOriginVar = taintFromInitializer;
      }
    }

    if (shouldTaint) {
      if (ts.isIdentifier(varNameNode)) {
        ctx.taintedVars.add(varNameNode.text);
      } else if (ts.isObjectBindingPattern(varNameNode) || ts.isArrayBindingPattern(varNameNode)) {
        for (const element of varNameNode.elements) {
          if (ts.isBindingElement(element) && ts.isIdentifier(element.name)) {
            ctx.taintedVars.add(element.name.text);
          }
        }
      }
    }
  } else if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
    if (ts.isIdentifier(node.left)) {
      const assignedVarName = node.left.text;
      const rightOperandExpr = node.right;
      const rightOperandText = rightOperandExpr.getText(sourceFile);

      let shouldTaint = false;
      let taintedOriginVar: string | null = null;

      if (TAINT_SOURCES.some((source) => rightOperandText.startsWith(source))) {
        shouldTaint = true;
        taintedOriginVar = rightOperandText;
      }

      if (!shouldTaint) {
        const taintFromRightOperand = isExpressionTainted(rightOperandExpr, ctx.taintedVars, sourceFile);
        if (taintFromRightOperand) {
          shouldTaint = true;
          taintedOriginVar = taintFromRightOperand;
        }
      }

      if (shouldTaint) {
        void taintedOriginVar;
        ctx.taintedVars.add(assignedVarName);
      }
    }
  }

  ts.forEachChild(node, (child) => findTaintedSources(child, ctx, sourceFile));
}

function findSqlSinks(
  node: ts.Node,
  ctx: TaintAnalysisContext,
  sourceFile: ts.SourceFile
): Finding[] {
  const out: Finding[] = [];

  if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
    const methodAccess = node.expression;
    const methodName = methodAccess.name.text;

    if ((SQL_SINK_METHODS as readonly string[]).includes(methodName)) {
      node.arguments.forEach((arg, index) => {
        const taintedSourceVar = isExpressionTainted(arg, ctx.taintedVars, sourceFile);
        if (taintedSourceVar) {
          const start = arg.getStart(sourceFile);
          const end = arg.getEnd();
          out.push({
            ruleId: 'sql-injection',
            severity: 'warning',
            message: `Potential SQL injection: tainted data from "${taintedSourceVar}" reaches SQL method "${methodName}" (argument ${index + 1}).`,
            suggestion: 'Use parameterized queries / prepared statements; never concatenate user input into SQL.',
            start,
            end,
            owasp: 'A03:2021-Injection',
          });
        }
      });
    }
  }

  ts.forEachChild(node, (child) => out.push(...findSqlSinks(child, ctx, sourceFile)));
  return out;
}

export const sqlInjectionRule: SecurityRule = {
  id: 'sql-injection',
  title: 'SQL injection',
  owasp: 'A03:2021-Injection',
  description: 'Detects tainted data flowing into common SQL driver methods.',
  analyze(ctx: RuleContext): readonly Finding[] {
    const taintCtx: TaintAnalysisContext = { taintedVars: new Set() };
    findTaintedSources(ctx.sourceFile, taintCtx, ctx.sourceFile);
    return findSqlSinks(ctx.sourceFile, taintCtx, ctx.sourceFile);
  },
};
