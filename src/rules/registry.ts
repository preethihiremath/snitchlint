import type { SecurityRule } from './ruleTypes';
import { sqlInjectionRule } from './sqlInjectionRule';
import { xssRule } from './xssRule';
import { secretRule } from './secretRule';
import { commandInjectionRule } from './commandInjectionRule';
import { evalRule } from './evalRule';
import { deserializationRule } from './deserializationRule';
import { weakCryptoRule } from './weakCryptoRule';
import { fileUploadRule } from './fileUploadRule';
import { cookieFlagsRule } from './cookieFlagsRule';
import { csrfRule } from './csrfRule';
import { openRedirectRule } from './openRedirectRule';
import { pathTraversalRule } from './pathTraversalRule';
import { ssrfRule } from './ssrfRule';
import { reactXssRule } from './reactXssRule';
import { authRule } from './authRule';
import { loggingRule } from './loggingRule';

/** Ordered registry — safe to append new rules. */
export const allSecurityRules: readonly SecurityRule[] = [
  sqlInjectionRule,
  xssRule,
  reactXssRule,
  secretRule,
  commandInjectionRule,
  evalRule,
  deserializationRule,
  weakCryptoRule,
  fileUploadRule,
  cookieFlagsRule,
  csrfRule,
  openRedirectRule,
  pathTraversalRule,
  ssrfRule,
  authRule,
  loggingRule,
];

export const defaultRuleIds: readonly string[] = allSecurityRules.map((r) => r.id);
