/**
 * Canonical JSON (spec section 5.1): RFC 8785 (JCS) with its hard parts removed.
 *
 *   - Numbers are integers within the safe range (no fraction, no exponent, no -0). JCS's number
 *     formatting is the hard part of the RFC; without floats every implementation agrees.
 *   - Text is valid UTF-8 with no byte order mark, strings hold no lone surrogates, and an object never
 *     repeats a key. At most 64 arrays and objects sit inside one another.
 *   - Objects are written with keys sorted by UTF-16 code units, arrays in order, no whitespace.
 *   - Strings escape `"` and `\`, write U+0008, U+0009, U+000A, U+000C and U+000D as `\b \t \n \f \r`,
 *     every other code point below U+0020 as `\u00xx` in lower-case hex, and everything else raw (`/`,
 *     U+007F, U+2028, U+2029 and `<>&` included). That is exactly ECMA-262's QuoteJSONString, which
 *     JSON.stringify implements, once lone surrogates (which it would escape) are refused.
 *
 * `parseStrict` refuses anything outside those rules, so a value it returns always has one canonical form.
 */

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export class CanonicalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CanonicalError';
  }
}

// ignoreBOM keeps a byte order mark in the text, so the parser can refuse it rather than skip it silently.
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** Parse JSON text or bytes under the canonical rules (any whitespace is fine; values must be canonical-able). */
export const parseStrict = (input: string | Uint8Array): Json => parseWithMembers(input).value;

/**
 * Parse as `parseStrict` does, and also return the exact text of each member value of the outermost object,
 * so a member that must arrive in canonical form (an envelope's message) can be checked as it arrived. Text
 * compares as its UTF-8 bytes do, since the input was valid UTF-8 and holds no lone surrogates.
 */
export function parseWithMembers(input: string | Uint8Array): { value: Json; members: Map<string, string> } {
  let text: string;
  if (typeof input === 'string') text = input;
  else {
    try {
      text = decoder.decode(input);
    } catch {
      throw new CanonicalError('The body is not valid UTF-8.');
    }
  }
  if (text.charCodeAt(0) === 0xfeff) throw new CanonicalError('A byte order mark is not allowed.');
  const p = new Parser(text);
  p.ws();
  const value = p.value(0);
  p.ws();
  if (p.i !== text.length) p.fail('Unexpected text after the JSON value');
  return { value, members: p.members };
}

/** At most this many arrays and objects inside one another. */
const MAX_DEPTH = 64;

class Parser {
  i = 0;
  s: string;
  /** The text of each member value of the outermost object. */
  members = new Map<string, string>();
  constructor(s: string) {
    this.s = s;
  }

  fail(what: string): never {
    throw new CanonicalError(`${what} at offset ${this.i}.`);
  }

  ws() {
    while (this.i < this.s.length) {
      const c = this.s.charCodeAt(this.i);
      if (c === 0x20 || c === 0x0a || c === 0x0d || c === 0x09) this.i++;
      else break;
    }
  }

  /** A value inside `depth` arrays and objects. */
  value(depth: number): Json {
    const c = this.s[this.i];
    if ((c === '{' || c === '[') && depth >= MAX_DEPTH) this.fail('Nested too deeply');
    if (c === '{') return this.object(depth);
    if (c === '[') return this.array(depth);
    if (c === '"') return this.string();
    if (c === 't') return this.literal('true', true);
    if (c === 'f') return this.literal('false', false);
    if (c === 'n') return this.literal('null', null);
    if (c === '-' || (c >= '0' && c <= '9')) return this.number();
    return this.fail('Expected a JSON value');
  }

  literal<T extends Json>(word: string, v: T): T {
    if (this.s.startsWith(word, this.i)) {
      this.i += word.length;
      return v;
    }
    return this.fail('Expected a JSON value');
  }

  number(): number {
    const m = /^-?(0|[1-9][0-9]*)([.eE])?/.exec(this.s.slice(this.i, this.i + 40));
    if (!m) this.fail('Invalid number');
    if (m[2]) this.fail('Numbers must be integers (no fraction or exponent)');
    const text = m[0];
    if (text === '-0') this.fail('-0 is not allowed');
    const n = Number(text);
    if (!Number.isSafeInteger(n)) this.fail('Integers must lie between -(2^53 - 1) and 2^53 - 1');
    this.i += text.length;
    return n;
  }

  string(): string {
    this.i++; // opening quote
    let out = '';
    let start = this.i;
    for (;;) {
      if (this.i >= this.s.length) this.fail('Unterminated string');
      const c = this.s.charCodeAt(this.i);
      if (c === 0x22) {
        out += this.s.slice(start, this.i);
        this.i++;
        break;
      }
      if (c < 0x20) this.fail('Control characters must be escaped in strings');
      if (c === 0x5c) {
        out += this.s.slice(start, this.i);
        const e = this.s[this.i + 1];
        const simple: Record<string, string> = {
          '"': '"',
          '\\': '\\',
          '/': '/',
          b: '\b',
          f: '\f',
          n: '\n',
          r: '\r',
          t: '\t',
        };
        if (e in simple) {
          out += simple[e];
          this.i += 2;
        } else if (e === 'u') {
          const hex = this.s.slice(this.i + 2, this.i + 6);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail('Invalid \\u escape');
          out += String.fromCharCode(parseInt(hex, 16));
          this.i += 6;
        } else this.fail('Invalid escape');
        start = this.i;
        continue;
      }
      this.i++;
    }
    if (!out.isWellFormed()) this.fail('Strings may not contain lone surrogates');
    return out;
  }

  array(depth: number): Json[] {
    this.i++;
    const out: Json[] = [];
    this.ws();
    if (this.s[this.i] === ']') {
      this.i++;
      return out;
    }
    for (;;) {
      this.ws();
      out.push(this.value(depth + 1));
      this.ws();
      const c = this.s[this.i++];
      if (c === ']') return out;
      if (c !== ',') this.fail('Expected , or ]');
    }
  }

  object(depth: number): { [key: string]: Json } {
    this.i++;
    const out: { [key: string]: Json } = Object.create(null);
    const seen = new Set<string>();
    this.ws();
    // Built on a null prototype, then copied, so a key named `__proto__` is an ordinary key.
    if (this.s[this.i] === '}') {
      this.i++;
      return { ...out };
    }
    for (;;) {
      this.ws();
      if (this.s[this.i] !== '"') this.fail('Expected a string key');
      const key = this.string();
      if (seen.has(key)) this.fail(`Duplicate key "${key}"`);
      seen.add(key);
      this.ws();
      if (this.s[this.i++] !== ':') this.fail('Expected :');
      this.ws();
      const start = this.i;
      out[key] = this.value(depth + 1);
      if (depth === 0) this.members.set(key, this.s.slice(start, this.i));
      this.ws();
      const c = this.s[this.i++];
      if (c === '}') return { ...out };
      if (c !== ',') this.fail('Expected , or }');
    }
  }
}

/** UTF-16 code unit order, as JCS sorts keys. */
function compareKeys(a: string, b: string) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * The canonical text of a value. Throws on anything outside the rules, so it never writes what the parser
 * would refuse: floats, undefined, lone surrogates, nesting past MAX_DEPTH, arrays with holes, and objects
 * that are not plain (a Date or a Map would otherwise become `{}`).
 */
export function canonicalize(value: unknown, depth = 0): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
        throw new CanonicalError(`Not an integer in range: ${value}`);
      }
      return String(value);
    case 'string':
      if (!value.isWellFormed()) throw new CanonicalError('Strings may not contain lone surrogates.');
      return JSON.stringify(value);
    case 'object': {
      if (depth >= MAX_DEPTH) throw new CanonicalError(`Nested more than ${MAX_DEPTH} deep.`);
      if (Array.isArray(value)) {
        const items = Array.from({ length: value.length }, (_, i) => {
          if (!(i in value)) throw new CanonicalError(`An array has a hole at ${i}.`);
          return canonicalize(value[i], depth + 1);
        });
        return `[${items.join(',')}]`;
      }
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) throw new CanonicalError('Not a plain object.');
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj);
      for (const k of keys) if (obj[k] === undefined) throw new CanonicalError(`Undefined value for "${k}".`);
      keys.sort(compareKeys);
      return `{${keys.map(k => `${canonicalize(k)}:${canonicalize(obj[k], depth + 1)}`).join(',')}}`;
    }
    default:
      throw new CanonicalError(`Not a JSON value: ${typeof value}`);
  }
}

/** The canonical bytes of a value. */
export function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(canonicalize(value), 'utf8');
}

/** Whether these bytes are exactly the canonical form of the value they hold. */
export function isCanonical(bytes: Uint8Array, value?: Json): boolean {
  const v = value === undefined ? parseStrict(bytes) : value;
  return Buffer.from(bytes).equals(canonicalBytes(v));
}

export const isJsonObject = (value: unknown): value is { [key: string]: Json } =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

/** The canonical bytes of a signed object without its `signature`: what a message id hashes. */
export function unsignedBytes(signed: object): Buffer {
  const { signature: _, ...unsigned } = signed as { signature?: unknown };
  return canonicalBytes(unsigned);
}

/** The line that starts the bytes of each kind of signed object, so no signature can be read as another kind. */
export type SigningContext =
  | 'SIMON-MESSAGE'
  | 'SIMON-ENVELOPE'
  | 'SIMON-CLAIMS'
  | 'SIMON-SIGNAL'
  | 'SIMON-AGENT'
  | 'SIMON-DIRECTORY';

/** What is signed: the context line, a newline, and the canonical bytes without `signature`. */
export const signingBytes = (context: SigningContext, signed: object): Buffer =>
  Buffer.concat([Buffer.from(`${context}\n`), unsignedBytes(signed)]);
