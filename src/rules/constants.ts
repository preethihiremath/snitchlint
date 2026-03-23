/**
 * Shared taint sources and sink names for injection-style rules.
 */

export const TAINT_SOURCES = [
  'req.body',
  'req.query',
  'req.params',
  'request.body',
  'request.query',
  'request.params',
  'ctx.request.body',
  'ctx.query',
  'ctx.params',
  'event.queryStringParameters',
  'event.body',
  'process.env',
  'window.location',
  'document.cookie',
  'localStorage.getItem',
  'sessionStorage.getItem',
] as const;

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
  'connection.execute',
] as const;
