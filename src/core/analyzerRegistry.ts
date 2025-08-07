import { Analyzer } from './analyzerTypes';
import { sqlInjectionAnalyzer } from '../analyzers/sqlInjectionAnalyzer';
import { xssAnalyzer } from '../analyzers/xssAnalyzer';
import { secretAnalyzer } from '../analyzers/secretAnalyzer';

export const analyzerRegistry: Analyzer[] = [
  sqlInjectionAnalyzer,
  xssAnalyzer,
  secretAnalyzer,
];
