/**
 * The policy module's inbound limits, per recipient per day (docs: app/docs/policy.md).
 *
 *   SIMON_INBOUND_PER_SENDER      messages from one sender on another server   (default 200)
 *   SIMON_INBOUND_PER_DOMAIN      messages from one domain on another server   (default 2000)
 *   SIMON_INBOUND_FIRST_CONTACTS  senders never heard from before, from anywhere (default 30)
 */
import { int, type Env } from '../../lib/env.ts';

export interface PolicyConfig {
  perSender: number;
  perDomain: number;
  firstContacts: number;
}

export const readPolicyConfig = (env: Env): PolicyConfig => ({
  perSender: int(env, 'SIMON_INBOUND_PER_SENDER', 200),
  perDomain: int(env, 'SIMON_INBOUND_PER_DOMAIN', 2000),
  firstContacts: int(env, 'SIMON_INBOUND_FIRST_CONTACTS', 30),
});
