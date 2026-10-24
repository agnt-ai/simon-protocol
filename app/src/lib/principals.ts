/**
 * Principals as this application reads them: the protocol's identifiers (spec section 2.2), written
 * `mailto:<address>`, `tel:+<E.164>` or `simon-key:<key token>`. People in the directory are found by
 * them, and the API takes and gives them in that form.
 */
import { invalid, isPrincipal, normalizeAddress } from '@agnt-protocol/protocol';

export type PrincipalKind = 'email' | 'phone' | 'key';

/** A principal in its one written form (an email address lowered, a number without spacing), or null. */
export function normalizePrincipal(input: string): string | null {
  const value = input.trim();
  if (value.startsWith('mailto:')) {
    const address = normalizeAddress(value.slice('mailto:'.length));
    return address ? `mailto:${address}` : null;
  }
  if (value.startsWith('tel:')) {
    const tel = `tel:${value.slice('tel:'.length).replace(/[\s().-]/g, '')}`;
    return isPrincipal(tel) ? tel : null;
  }
  return isPrincipal(value) ? value : null;
}

export function principalArg(field: string, value: string): string {
  const principal = normalizePrincipal(value);
  if (!principal) throw invalid(`${field} is a mailto:, tel: or simon-key: identifier.`, { field });
  return principal;
}

export const kindOf = (principal: string): PrincipalKind =>
  principal.startsWith('mailto:') ? 'email' : principal.startsWith('tel:') ? 'phone' : 'key';

/** The email address or phone number a principal names; null for a key. */
export function reachOf(principal: string): string | null {
  const kind = kindOf(principal);
  return kind === 'key' ? null : principal.slice(kind === 'email' ? 'mailto:'.length : 'tel:'.length);
}

/** The domain of an email principal, or null. */
export const emailDomain = (principal: string) =>
  kindOf(principal) === 'email' ? principal.slice(principal.lastIndexOf('@') + 1) : null;

/** A principal with most of it hidden, to say where a code went: `mailto:a*****@example.com`. */
export function masked(principal: string): string {
  const kind = kindOf(principal);
  if (kind === 'email') {
    const [local, domain] = principal.slice('mailto:'.length).split('@');
    return `mailto:${local[0]}${'*'.repeat(Math.min(6, Math.max(1, local.length - 1)))}@${domain}`;
  }
  if (kind === 'phone')
    return `${principal.slice(0, 7)}${'*'.repeat(Math.max(1, principal.length - 9))}${principal.slice(-2)}`;
  return `${principal.slice(0, 20)}...`;
}
