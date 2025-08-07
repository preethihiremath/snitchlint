import { Analyzer } from './analyzerTypes';
import { sqlInjectionAnalyzer } from '../analyzers/sqlInjectionAnalyzer';
import { xssAnalyzer } from '../analyzers/xssAnalyzer';
import { secretAnalyzer } from '../analyzers/secretAnalyzer';
import { commandInjectionAnalyzer } from '../analyzers/commandInjectionAnalyzer';
import { evalFunctionAnalyzer } from '../analyzers/evalFunctionAnalyzer';
import { deserializationAnalyzer } from '../analyzers/deserializationAnalyzer';
import { weakCryptoAnalyzer } from '../analyzers/weakCryptoAnalyzer';
import { fileUploadAnalyzer } from '../analyzers/fileUploaderAnalyzer';
import { cookieFlagsAnalyzer } from '../analyzers/cookieFlagsAnalyzer';
import { csrfAnalyzer } from '../analyzers/csrfAnalyzer';
import { openRedirectAnalyzer } from '../analyzers/openRedirectAnalyzer';

export const analyzerRegistry: Analyzer[] = [
  sqlInjectionAnalyzer,
  xssAnalyzer,
  secretAnalyzer,
  commandInjectionAnalyzer,
  evalFunctionAnalyzer,
  deserializationAnalyzer,
  weakCryptoAnalyzer,
  fileUploadAnalyzer,
  cookieFlagsAnalyzer,
  csrfAnalyzer,
  openRedirectAnalyzer
];
