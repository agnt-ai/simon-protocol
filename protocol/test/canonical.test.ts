/** Canonical JSON: the strict parser, and the one form every value it accepts has. */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalize,
  CanonicalError,
  isCanonical,
  parseStrict,
  parseWithMembers,
  signingBytes,
} from '../src/index.ts';

const canon = (text: string) => canonicalize(parseStrict(text));

const cp = (...points: number[]) => String.fromCodePoint(...points);

describe('canonical JSON', () => {
  it('keys sort by UTF-16 code units, whitespace goes, arrays keep their order', () => {
    assert.equal(canon('{ "b": 1, "a": [3, 1, 2], "A": true }'), '{"A":true,"a":[3,1,2],"b":1}');
    // By code unit: U+00E9 < U+20AC < U+1F600 (stored as D83D DE00) < U+FB01, unlike code point order.
    const [eAcute, euro, grin, ligature] = [cp(0xe9), cp(0x20ac), cp(0x1f600), cp(0xfb01)];
    const input = JSON.stringify({ [euro]: 1, [eAcute]: 2, [ligature]: 3, [grin]: 4 });
    assert.equal(canon(input), `{"${eAcute}":2,"${euro}":1,"${grin}":4,"${ligature}":3}`);
  });

  it('strings are escaped exactly as section 5.1 lists, and nothing else is', () => {
    // The five short escapes, then \u00xx in lower-case hex for the other controls.
    assert.equal(canon(String.raw`"\b\t\n\f\r\u0000\u001F\u000B\"\\"`), String.raw`"\b\t\n\f\r\u0000\u001f\u000b\"\\"`);
    // Everything else raw: "/", DEL, the two line separators, HTML's specials and non-ASCII text.
    const input = String.raw`"\/ \u007f \u2028 \u2029 \u003c\u003e\u0026 \u00e9 \ud83d\ude00"`;
    assert.equal(canon(input), `"/ ${cp(0x7f)} ${cp(0x2028)} ${cp(0x2029)} <>& ${cp(0xe9)} ${cp(0x1f600)}"`);
  });

  it('integers in the safe range are the only numbers', () => {
    assert.equal(canon('[0, -1, 9007199254740991, -9007199254740991]'), '[0,-1,9007199254740991,-9007199254740991]');
    for (const bad of ['1.0', '1e3', '-0', '9007199254740992', '01', '.5']) {
      assert.throws(() => parseStrict(bad), `${bad} should be refused`);
    }
  });

  it('duplicate keys, lone surrogates, invalid UTF-8 and trailing text are refused', () => {
    assert.throws(() => parseStrict('{"a":1,"a":2}'), /Duplicate key/);
    assert.throws(() => parseStrict('"\\ud800"'), /lone surrogates/);
    assert.throws(() => parseStrict(Buffer.from([0x22, 0xff, 0x22])), /UTF-8/);
    assert.throws(() => parseStrict('{} x'), /after the JSON value/);
    assert.throws(() => parseStrict(`${cp(0xfeff)}{}`), /byte order mark/);
  });

  it('isCanonical compares the exact bytes', () => {
    assert.equal(isCanonical(Buffer.from('{"a":1,"b":2}')), true);
    assert.equal(isCanonical(Buffer.from('{"b":2,"a":1}')), false);
    assert.equal(isCanonical(Buffer.from('{"a": 1}')), false);
  });

  it('a key named __proto__ is an ordinary key', () => {
    assert.equal(canon('{"__proto__":1,"a":2}'), '{"__proto__":1,"a":2}');
  });

  it('nesting stops at 64 arrays and objects', () => {
    assert.doesNotThrow(() => parseStrict(`${'['.repeat(64)}${']'.repeat(64)}`));
    assert.throws(() => parseStrict(`${'['.repeat(65)}${']'.repeat(65)}`), /Nested too deeply/);
  });

  it('the writer never writes what the parser refuses: deep nesting, holes, objects that are not plain', () => {
    const nest = (n: number): unknown => (n === 0 ? 1 : [nest(n - 1)]);
    assert.doesNotThrow(() => parseStrict(canonicalize(nest(64))));
    assert.throws(() => canonicalize(nest(65)), CanonicalError);
    assert.throws(() => canonicalize([, 1]), CanonicalError);
    assert.throws(() => canonicalize({ at: new Date(0) }), CanonicalError);
    assert.throws(() => canonicalize(new Map()), CanonicalError);
    assert.equal(canonicalize(Object.assign(Object.create(null), { a: 1 })), '{"a":1}');
  });

  it('the members of the outermost object keep the text they were sent as', () => {
    const { value, members } = parseWithMembers('{ "m" : {"b": 1,"a":2} , "n":[ 1 ] }');
    assert.deepEqual(value, { m: { a: 2, b: 1 }, n: [1] });
    assert.equal(members.get('m'), '{"b": 1,"a":2}');
    assert.equal(members.get('n'), '[ 1 ]');
    assert.equal(parseWithMembers('[{"m":1}]').members.size, 0);
  });

  it('signing bytes are a context line, a newline, and the canonical form without signature', () => {
    assert.equal(signingBytes('SIMON-AGENT', { b: 1, signature: 'x', a: 2 }).toString(), 'SIMON-AGENT\n{"a":2,"b":1}');
  });
});
