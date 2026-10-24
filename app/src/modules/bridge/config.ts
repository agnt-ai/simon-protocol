/**
 * The email bridge. Mail goes out from `no-reply@<domain>` with a reply address `reply+<token>@<domain>`;
 * the operator's inbound-mail provider posts replies to `/api/bridge/inbound` with the secret.
 *
 *   AGNT_BRIDGE_DOMAIN          the domain bridge mail is sent from and replies come to (default: AGNT_SYSTEM_DOMAIN)
 *   AGNT_BRIDGE_INBOUND_SECRET  what the inbound-mail provider presents (required outside development)
 */
import { normalizeDomain } from '@agnt-protocol/protocol';
import { fail, text, type Env } from '../../lib/env.ts';

export interface BridgeConfig {
  domain: string;
  /** Null: no replies are taken. */
  inboundSecret: string | null;
}

export function readBridgeConfig(env: Env, dev: boolean, systemDomain: string): BridgeConfig {
  const domain = text(env, 'AGNT_BRIDGE_DOMAIN') ?? systemDomain;
  if (normalizeDomain(domain) !== domain) fail(`AGNT_BRIDGE_DOMAIN ${domain} is not a domain.`);
  const inboundSecret = text(env, 'AGNT_BRIDGE_INBOUND_SECRET');
  if (!inboundSecret && !dev)
    fail('AGNT_BRIDGE_INBOUND_SECRET is required for the bridge to take replies; or leave bridge out of AGNT_MODULES.');
  return { domain, inboundSecret };
}
