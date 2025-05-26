
import { parse } from '@typescript-eslint/parser'; 
import { TSESTree } from '@typescript-eslint/types';

interface ASTParseResult {
  ast: TSESTree.Program | null;
  error?: Error;
}

/**
 * Parses TypeScript/JavaScript code into an ESTree-compatible AST.
 * Returns the AST or error if parsing fails.
 */
// export function parseCodeToAST(code: string): ASTParseResult {
//   try {
//     const ast = parse(code, {
//       loc: true,
//       range: true,
//       comment: true,
//       ecmaVersion: 2020,
//       sourceType: 'module',
//     }) as TSESTree.Program;

//     return { ast };
//   } catch (error) {
//     return { ast: null, error: error as Error };
//   }
// }

/**
 * Taint source identifiers: expressions that represent user-controlled inputs.
 * This list is more comprehensive and aims to match common input patterns.
 */
export const TAINT_SOURCES = [
  'req.body',
  'req.query',
  'req.params',
  'request.body', // Common alias
  'request.query',
  'request.params',
  'ctx.request.body', // Koa.js style
  'ctx.query',        // Koa.js style
  'ctx.params',       // Koa.js style
  'event.queryStringParameters', // AWS Lambda
  'event.body', // AWS Lambda
  'process.env', 
  'window.location',
  'document.cookie',
  'localStorage.getItem',
  'sessionStorage.getItem',
];

/**
 * List of known SQL execution method names.
 */
export const SQL_SINK_METHODS = [
    'query',
    'execute',
    'exec', 
    'prepare', 
    'raw', 
    'connect.query', 
    'db.query',
    'db.execute',       
    'db.raw',   
    'db.prepare',
  'connection.query',
  'connection.execute'
];