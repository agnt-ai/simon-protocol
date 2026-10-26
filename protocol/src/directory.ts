/**
 * Directory records (discovery profile, section 1): an issuer's signed word that the holder of an email
 * address or a phone number chose an assistant. The identifier's own domain issues them for its addresses
 * when its `_simon` TXT record names a server; directories a reader trusts issue them for everything else.
 *
 *   {"identifier","address","revision","issued","expires","issuer","signature"}
 *
 * signed by the issuer over `SIMON-DIRECTORY\n` and the canonical record without `signature`, with a key of
 * its server document valid at `issued`. A record lasts at most 366 days, as a pairing does.
 */
import type { KeyObject } from 'node:crypto';
import { isV1Address } from './address.ts';
import { signingBytes, isJsonObject } from './canonical.ts';
import { isB64url, sign, signedByAny, type KeyEntry } from './keys.ts';
import { isPrincipal, PAIRING_MAX_MS } from './principal.ts';
import { serverOrigin } from './resolve.ts';
import { parseTimestamp } from './time.ts';
import { SENT_AT_FUTURE_MS } from './limits.ts';

export interface DirectoryRecord {
  /** A `mailto:` or `tel:` identifier. */
  identifier: string;
  /** The assistant its holder chose. */
  address: string;
  /** Higher for each later choice its issuer records for the identifier. */
  revision: number;
  issued: string;
  expires: string;
  /** The origin of the server that signed it. */
  issuer: string;
  signature: string;
}

/** The longest a record lasts from when it was issued: as long as a pairing may. */
export const RECORD_MAX_MS = PAIRING_MAX_MS;

/** Whether a value is an identifier a directory record may name: a `mailto:` or `tel:` principal. */
export const isListableIdentifier = (value: unknown): value is string =>
  isPrincipal(value) && !value.startsWith('simon-key:');

/** The bytes an issuer signs for a record. */
export const directoryBytes = (record: Omit<DirectoryRecord, 'signature'>) => signingBytes('SIMON-DIRECTORY', record);

/** A record signed by `issuerKey`, a key of the issuer's server document. */
export function signDirectoryRecord(
  record: Omit<DirectoryRecord, 'signature'>,
  issuerKey: string | KeyObject,
): DirectoryRecord {
  return { ...record, signature: sign(issuerKey, directoryBytes(record)) };
}

/**
 * The record `value` is, when a reader may take it at `now` for `identifier` (discovery profile, section 1):
 * every member well formed, for that identifier, issued at most 5 minutes ahead of `now`, not yet expired,
 * lasting at most 366 days, and signed by one of `issuerKeys`, the issuer's server keys, valid at `issued`.
 * Otherwise null. Members it does not know are dropped. `issuer` is an https origin, written as resolution
 * writes one; `allowHttp` admits http ones too, for local development only.
 */
export function readDirectoryRecord(
  value: unknown,
  identifier: string,
  issuerKeys: readonly KeyEntry[],
  now: Date,
  allowHttp = false,
): DirectoryRecord | null {
  if (!isJsonObject(value)) return null;
  const { identifier: id, address, revision, issued, expires, issuer, signature } = value as Record<string, unknown>;
  const [from, to] = [parseTimestamp(issued), parseTimestamp(expires)];
  if (
    id !== identifier ||
    !isListableIdentifier(id) ||
    !isV1Address(address) ||
    !Number.isSafeInteger(revision) ||
    (revision as number) < 1 ||
    from === null ||
    to === null ||
    !(from < to && to - from <= RECORD_MAX_MS) ||
    from > now.getTime() + SENT_AT_FUTURE_MS ||
    now.getTime() >= to ||
    typeof issuer !== 'string' ||
    serverOrigin(issuer, allowHttp) !== issuer ||
    !isB64url(signature)
  ) {
    return null;
  }
  const record = { identifier: id, address, revision: revision as number, issued, expires, issuer } as Omit<
    DirectoryRecord,
    'signature'
  >;
  try {
    if (!signedByAny(issuerKeys, new Date(from), directoryBytes(record), signature)) return null;
  } catch {
    return null;
  }
  return { ...record, signature: signature as string };
}
