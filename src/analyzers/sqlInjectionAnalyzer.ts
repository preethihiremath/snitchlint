import * as ts from 'typescript';
import * as vscode from 'vscode';
import { TAINT_SOURCES, SQL_SINK_METHODS } from '../utils/astUtils';


interface TaintAnalysisContext {
  taintedVars: Set<string>;
}

/**
 * Main analysis function for SQL injection.
 */
export function analyzeSqlInjection(doc: vscode.TextDocument): vscode.Diagnostic[] {
  console.log(`[SnitchLint-SQL] Running for: ${doc.fileName}`);
  const diagnostics: vscode.Diagnostic[] = [];

  const sourceFile = ts.createSourceFile(
    doc.fileName,
    doc.getText(),
    ts.ScriptTarget.Latest,
    true // Set to true for full source map support
  );

  const context: TaintAnalysisContext = {
    taintedVars: new Set(),
  };

  findTaintedSources(sourceFile, context, sourceFile); //getText(sourceFile) requires the sourceFile context for retrieving node text.
  diagnostics.push(...findSqlSinks(sourceFile, context, doc, sourceFile));

  if (diagnostics.length > 0) {
    console.log(`[SnitchLint-SQL] Found ${diagnostics.length} potential issues in ${doc.fileName}`);
  }
  return diagnostics;
}

/*
    * Recursively traverses the AST to find tainted sources.
    * Tainted sources are typically user inputs or other untrusted data that can lead to SQL injection.
    *
    * @param node The current AST node being analyzed.
    * @param ctx The taint analysis context containing tainted variables.
    * @param sourceFile The TypeScript source file representation of the document.
    */
function findTaintedSources(node: ts.Node, ctx: TaintAnalysisContext, sourceFile: ts.SourceFile) {
    // 1. Check for Variable Declarations (e.g., const userId = req.query.id;)
    if (ts.isVariableDeclaration(node) && node.initializer) {
        const varNameNode = node.name; // This can be Identifier or BindingPattern
        const initializerExpr = node.initializer;
        const initializerText = initializerExpr.getText(sourceFile); // Get full text of initializer

        let shouldTaint = false;
        let taintedOriginVar: string | null = null; // To log which variable/source caused the taint

        // A. Check if the initializer expression itself is a direct taint source (using startsWith as per your current TAINT_SOURCES)
        if (TAINT_SOURCES.some(source => initializerText.startsWith(source))) {
            shouldTaint = true;
            taintedOriginVar = initializerText;
        }

        // B. Check if the initializer expression *contains* a variable that is already tainted (taint propagation)
        // This handles cases like: `const queryStr = `SELECT * FROM users WHERE id = ${taintedId}`;`
        // Or: `const processedId = process(taintedId);`
        if (!shouldTaint) { // Only run this if not already directly tainted by A.
            const taintFromInitializer = isExpressionTainted(initializerExpr, ctx.taintedVars, sourceFile);
            if (taintFromInitializer) {
                shouldTaint = true;
                taintedOriginVar = taintFromInitializer;
            }
        }

        if (shouldTaint) {
            if (ts.isIdentifier(varNameNode)) {
                console.log(`[SnitchLint-SQL] Tainted source (Variable Decl.): ${varNameNode.text} from "${taintedOriginVar}"`);
                ctx.taintedVars.add(varNameNode.text);
            } else if (ts.isObjectBindingPattern(varNameNode) || ts.isArrayBindingPattern(varNameNode)) {
                // For destructuring: if the initializer is tainted, all destructured variables are tainted
                // A more advanced approach would try to match specific properties if applicable,
                // but for now, if the source is tainted, the destructured elements are too.
                varNameNode.elements.forEach(element => {
                    if (ts.isBindingElement(element) && ts.isIdentifier(element.name)) {
                        console.log(`[SnitchLint-SQL] Tainted source (Destructured Decl.): ${element.name.text} from "${taintedOriginVar}"`);
                        ctx.taintedVars.add(element.name.text);
                    }
                });
            }
        }
    }
    // 2. Check for Binary Assignments (e.g., userId = req.body.id; or query = taintedSql;)
    else if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        if (ts.isIdentifier(node.left)) {
            const assignedVarName = node.left.text;
            const rightOperandExpr = node.right;
            const rightOperandText = rightOperandExpr.getText(sourceFile); // Get full text of right operand

            let shouldTaint = false;
            let taintedOriginVar: string | null = null;

            // A. Check if the right-hand side is a direct taint source (using startsWith)
            if (TAINT_SOURCES.some(source => rightOperandText.startsWith(source))) {
                shouldTaint = true;
                taintedOriginVar = rightOperandText;
            }

            // B. Check if the right-hand side expression *contains* a variable that is already tainted (taint propagation)
            // This handles cases like: `myQuery = `SELECT * FROM users WHERE id = ${userId}`;`
            if (!shouldTaint) { // Only run this if not already directly tainted by A.
                const taintFromRightOperand = isExpressionTainted(rightOperandExpr, ctx.taintedVars, sourceFile);
                if (taintFromRightOperand) {
                    shouldTaint = true;
                    taintedOriginVar = taintFromRightOperand;
                }
            }

            if (shouldTaint) {
                console.log(`[SnitchLint-SQL] Taint propagated via assignment: ${assignedVarName} from "${taintedOriginVar}"`);
                ctx.taintedVars.add(assignedVarName);
            }
        }
    }

    // Continue recursive traversal for all children nodes
    ts.forEachChild(node, child => findTaintedSources(child, ctx, sourceFile));
}

/*
    * Checks if an expression is tainted by looking for identifiers or property accesses
    * that match tainted variables in the current scope.
    *
    * @param expr The expression to check.
    * @param taintedVarsInScope The set of tainted variable names in the current scope.
    * @param sourceFile The TypeScript source file representation of the document.
    * @returns The name of the tainted variable if found, otherwise null.
    */
function isExpressionTainted(expr: ts.Expression, taintedVarsInScope: Set<string>, sourceFile: ts.SourceFile): string | null {
    // 1. Check if the expression is a direct reference to a tainted variable (Identifier)
    if (ts.isIdentifier(expr)) {
        // If the expression is a variable, check if its name is in our tainted set
        return taintedVarsInScope.has(expr.text) ? expr.text : null;
    }
    // 2. Check if the expression is a property access (e.g., 'obj.prop', 'obj.prop.value')
    else if (ts.isPropertyAccessExpression(expr)) {
        // If it's `obj.prop`, we need to find the base object (`obj`)
        // and check if that base object itself is tainted.
        let current: ts.Expression = expr;
        // Traverse up the property access chain until we reach the base identifier
        // e.g., for `a.b.c`, this loop will get `current` to `a`
        while (ts.isPropertyAccessExpression(current)) {
            current = current.expression;
        }
        // If the base expression is an identifier AND that identifier is in our tainted set,
        // then the entire property access expression is considered tainted.
        if (ts.isIdentifier(current) && taintedVarsInScope.has(current.text)) {
            return current.text; // Return the base variable name that is tainted
        }
    }
    // 3. Check if the expression is a binary operation, specifically string concatenation (A + B)
    else if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.PlusToken) {
        // For string concatenations: if either the left-hand side or the right-hand side
        // is tainted, the whole resulting string expression is considered tainted.
        const leftTaint = isExpressionTainted(expr.left, taintedVarsInScope, sourceFile);
        if (leftTaint) {
            return leftTaint; // Found taint on the left side
        }
        const rightTaint = isExpressionTainted(expr.right, taintedVarsInScope, sourceFile);
        if (rightTaint) {
            return rightTaint; // Found taint on the right side
        }
    }
    // 4. Check if the expression is a template literal (e.g., `Hello ${name}!`)
    else if (ts.isTemplateExpression(expr)) {
        // For template literals: iterate through all interpolated parts (templateSpans).
        // If any interpolated expression (e.g., `${name}`) is tainted, the whole template literal is tainted.
        for (const span of expr.templateSpans) {
            const spanTaint = isExpressionTainted(span.expression, taintedVarsInScope, sourceFile);
            if (spanTaint) {
                return spanTaint; // Found taint within an interpolated span
            }
        }
    }
    // 5. (Optional, more advanced) Check for Call Expressions (e.g., function returns tainted data)
    // This part is more complex and typically requires a "function summary" model
    // to know if a function's return value is tainted based on its arguments.
    // For a basic implementation, a common heuristic is to assume a return value is tainted
    // if any of its arguments are tainted (but this can lead to false positives if the function sanitizes).
    /*
    else if (ts.isCallExpression(expr)) {
        for (const arg of expr.arguments) {
            const argTaint = isExpressionTainted(arg, taintedVarsInScope, sourceFile);
            if (argTaint) {
                // Heuristic: If any argument is tainted, assume the function's output is also tainted.
                // This is a simplification and might lead to false positives if the function sanitizes.
                return argTaint;
            }
        }
    }
    */

    // If none of the above checks found taint, the expression is considered untainted.
    return null;
}

/*
    * Finds SQL sink methods in the AST and checks if they are called with tainted arguments.
    * 
    * @param node The current AST node being analyzed.
    * @param ctx The taint analysis context containing tainted variables.
    * @param doc The VS Code text document being analyzed.
    * @param sourceFile The TypeScript source file representation of the document.
    * @returns An array of diagnostics for potential SQL injection issues.
    */
function findSqlSinks(
  node: ts.Node,
  ctx: TaintAnalysisContext,
  doc: vscode.TextDocument,
  sourceFile: ts.SourceFile
): vscode.Diagnostic[] {
  const diagnostics: vscode.Diagnostic[] = [];
// Checks if the current node is a function call where the function is accessed as a property of an object 
  if (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression)
  ) {
    const methodAccess = node.expression;
    const methodName = methodAccess.name.text;

    if (SQL_SINK_METHODS.includes(methodName)) {
     
      node.arguments.forEach((arg, index) => {
        const taintedSourceVar = isExpressionTainted(arg, ctx.taintedVars, sourceFile);
        if (taintedSourceVar) {
          const start = doc.positionAt(arg.getStart(sourceFile));
          const end = doc.positionAt(arg.getEnd());
          const message = `⚠️ [SnitchLint-SQL] Potential SQL Injection: Tainted data from "${taintedSourceVar}" used in SQL method "${methodName}" argument ${index + 1}.`;
          diagnostics.push(new vscode.Diagnostic(
            new vscode.Range(start, end),
            message,
            vscode.DiagnosticSeverity.Warning
          ));
          console.log(`[SnitchLint-SQL] SINK: ${methodName} called with tainted arg from "${taintedSourceVar}": ${arg.getText(sourceFile).substring(0,100)}`);
        }
      });
    }
  }
  ts.forEachChild(node, child => diagnostics.push(...findSqlSinks(child, ctx, doc, sourceFile)));
  return diagnostics;
}