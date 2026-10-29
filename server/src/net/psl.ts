/**
 * Registrable domains, by the ICANN section of the Public Suffix List (protocol.md section 11.2): the name one
 * label below a domain's public suffix, so every new subdomain of one domain shares one bound on lookups.
 *
 * The list's private section (github.io, and other hosts that give out subdomains) is left out on purpose:
 * lookups of random names under such a host all land on that host's DNS, which is the party a bound on
 * amplification protects, so they share its bound. The ICANN section alone is what keeps `example.co.uk` and
 * `example.com` apart from their neighbours.
 *
 * The rules ship with the server (`public-suffixes.ts`, a pinned snapshot); `loadPublicSuffixes` reads a newer
 * copy of the whole list instead. Matching is the list's own algorithm: an exception rule (`!`) wins, then the
 * rule with the most labels, `*` matching any one label; a name no rule matches has its last label as suffix.
 */
import fs from 'node:fs';
import { domainToASCII } from 'node:url';
import { PUBLIC_SUFFIX_RULES } from './public-suffixes.ts';

export interface PublicSuffixes {
  rules: Set<string>;
  exceptions: Set<string>;
}

/** The rules of a list's text: its ICANN section when it marks one, else every rule; labels as A-labels. */
export function parsePublicSuffixes(text: string): PublicSuffixes {
  const begin = text.indexOf('===BEGIN ICANN DOMAINS===');
  const end = text.indexOf('===END ICANN DOMAINS===');
  // From the start of the marker's line, so the marker is read with its line's `//` and is not a rule.
  const section = begin >= 0 && end > begin ? text.slice(text.lastIndexOf('\n', begin) + 1, end) : text;
  const rules = new Set<string>();
  const exceptions = new Set<string>();
  for (const line of section.split('\n')) {
    const rule = line.trim().split(/\s/)[0];
    if (!rule || rule.startsWith('//')) continue;
    const exception = rule.startsWith('!');
    const ascii = (exception ? rule.slice(1) : rule)
      .split('.')
      .map(label => aLabel(label))
      .join('.');
    (exception ? exceptions : rules).add(ascii);
  }
  return { rules, exceptions };
}

/**
 * A rule's label as an A-label: an ASCII label as it is, lower-cased (domainToASCII would read an all-digit
 * label as an IPv4 address: "0" becomes "0.0.0.0"), and only a Unicode label converted.
 */
function aLabel(label: string): string {
  if (label === '*' || /^[\x21-\x7e]+$/.test(label)) return label.toLowerCase();
  return domainToASCII(label) || label.toLowerCase();
}

let shipped: PublicSuffixes | null = null;

/** The snapshot that ships with the server. */
export const shippedPublicSuffixes = () => (shipped ??= parsePublicSuffixes(PUBLIC_SUFFIX_RULES));

/** The fewest rules a copy of the list's ICANN section is taken with: the 2024 list has about 6900. */
export const MIN_PUBLIC_SUFFIX_RULES = 5000;

/**
 * A copy of the list read from a file, for a server whose operator keeps a newer one. It must mark its ICANN
 * section and hold at least MIN_PUBLIC_SUFFIX_RULES rules there; anything else (an empty file, an error page,
 * a list without its section markers, which would bring in the private section) throws, so the server does
 * not start on it.
 */
export function loadPublicSuffixes(file: string): PublicSuffixes {
  const text = fs.readFileSync(file, 'utf8');
  if (!text.includes('===BEGIN ICANN DOMAINS===') || !text.includes('===END ICANN DOMAINS===')) {
    throw new Error(`${file} is not the Public Suffix List: it marks no ICANN section.`);
  }
  const list = parsePublicSuffixes(text);
  if (list.rules.size < MIN_PUBLIC_SUFFIX_RULES) {
    throw new Error(
      `${file} has ${list.rules.size} ICANN rules, fewer than the ${MIN_PUBLIC_SUFFIX_RULES} a whole list has.`,
    );
  }
  return list;
}

/** How many labels of `labels` (a domain's, in order) its public suffix takes. */
function suffixLength(labels: string[], list: PublicSuffixes): number {
  let longest = 1;
  for (let n = labels.length; n >= 1; n--) {
    const tail = labels.slice(labels.length - n);
    const name = tail.join('.');
    if (list.exceptions.has(name)) return n - 1;
    const wild = ['*', ...tail.slice(1)].join('.');
    if (n > longest && (list.rules.has(name) || list.rules.has(wild))) longest = n;
  }
  return longest;
}

/**
 * A domain's registrable domain: its public suffix and one label more. A domain that is itself a public
 * suffix, or shorter, is its own.
 */
export function registrableDomain(domain: string, list: PublicSuffixes = shippedPublicSuffixes()): string {
  const labels = domain.toLowerCase().replace(/\.$/, '').split('.');
  const n = suffixLength(labels, list);
  return n >= labels.length ? labels.join('.') : labels.slice(labels.length - n - 1).join('.');
}
