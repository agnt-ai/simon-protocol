/**
 * Text this application repeats to other people and their agents (a name, an organisation's name, a
 * private note) may not carry a link, a domain, an address or a phone number, so nobody can use it to
 * deliver one, nor characters a reader cannot see, so nothing hides in it. The rule is blunt on purpose:
 * any token with a dot inside it is refused, because every domain, link and email address has one, and a
 * list of top-level domains would always be out of date. Names and notes keep the same rule.
 *
 * Text is checked in its compatibility form (NFKC), so full-width and other lookalike digits, dots and
 * at signs count as the ASCII ones, and dot-like marks NFKC keeps apart (a middle dot, a katakana dot)
 * count as dots. What is stored is what was written.
 */
import { invalid } from '@agnt-protocol/protocol';

/** A dot, or a mark that reads as one, with something other than space or a dot on each side. */
const DOTTED = /[^\s.。·‧∙⋅・⸱۔ꓸ][.。·‧∙⋅・⸱۔ꓸ][^\s.。·‧∙⋅・⸱۔ꓸ]/u;
/** Seven or more digits of any script, with a few spaces, brackets, dots or dashes of any kind between each. */
const PHONE = /(\+?\p{Nd}[\s().\p{Pd}]{0,3}){7,}/u;
/** Control and format characters: zero-width spaces and joiners, direction overrides, tags. */
const INVISIBLE = /[\p{Cc}\p{Cf}]/u;

/** Whether text holds a link, a domain or an address. */
export const hasLink = (s: string) => {
  const t = s.normalize('NFKC');
  return DOTTED.test(t) || t.includes('@') || /:\/\//.test(t);
};
export const hasPhone = (s: string) => PHONE.test(s.normalize('NFKC'));

/** Refuse a name, label or note with a link, a domain, an address, a phone number or an invisible character. */
export function plainText(field: string, value: string): string {
  if (INVISIBLE.test(value)) throw invalid(`${field} may not contain invisible or control characters.`, { field });
  if (hasPhone(value)) throw invalid(`${field} may not contain a phone number.`, { field });
  if (hasLink(value)) {
    throw invalid(`${field} may not contain a link, a domain or an address (no dotted words, no @).`, { field });
  }
  return value;
}
