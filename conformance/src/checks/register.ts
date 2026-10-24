/** CLIENT lifecycle: registration and pairing, keys, dedicated recovery/cancellation and unpairing. */
import crypto from 'node:crypto';
import {
  addKeyProofString,
  isV1Address,
  keyToken,
  parseTimestamp,
  sign,
  signPairing,
  signRecovery,
  signUnpairing,
  validAt,
  verifyUnpairing,
} from '@agnt-protocol/protocol';
import { TargetAgent } from '../agent.ts';
import { Prerequisite, type Ctx } from '../context.ts';
import { problem, sleep, type Res, type T } from '../harness.ts';
import { agentDocument, def, lists, readSync } from './common.ts';

const S = 'CLIENT register';
const R = 'CLIENT Recovery';
const C = 'CLIENT Cancelling a recovery';

/** Whether the server leases addresses, as a first register with a key alone shows. */
const leasing = (ctx: Ctx) =>
  ctx.once('whether the server leases addresses', async t => {
    const a = TargetAgent.fresh(ctx.server);
    const res = await a.register(t, {}, {}, 'register with a key alone');
    if (res.status === 200) return true;
    if (res.status === 400 && problem(res)?.code === 'address_required') {
      ctx.notes.push('The server leases no addresses (400 address_required).');
      return false;
    }
    throw new Prerequisite(`register with a key alone answered ${res.status} ${problem(res)?.code ?? ''}`);
  });

async function requireLeasing(ctx: Ctx) {
  if (!(await leasing(ctx))) throw new Prerequisite('the server leases no addresses');
}

export function requireHosted(ctx: Ctx) {
  if (!ctx.opts.hostedDomain) throw new Prerequisite('no --hosted-domain was given');
  return ctx.opts.hostedDomain;
}

/** A 200 account answer for `address` (any, when absent) that lists `token`. */
function accountAnswer(t: T, res: Res, token: string, address?: string, what = '') {
  const p = what ? `${what}: ` : '';
  t.status(res, 200, what);
  const b = res.json;
  t.assert(Array.isArray(b?.grants), `${p}grants is not an array`);
  t.assert(
    b.recovery === null ||
      (typeof b.recovery === 'object' &&
        b.recovery !== null &&
        parseTimestamp(b.recovery.completesAt) !== null &&
        typeof b.recovery.cancellable === 'boolean'),
    `${p}recovery is neither null nor a pending recovery`,
  );
  t.assert(
    typeof b.address === 'string' && isV1Address(b.address),
    `${p}address ${JSON.stringify(b.address)} is not an address in lower case`,
  );
  if (address) t.assert(b.address === address, `${p}address is ${b.address}, expected ${address}`);
  t.assert(
    Array.isArray(b.keys) && lists(b.keys, token),
    `${p}keys does not list ${token}: ${JSON.stringify(b.keys)?.slice(0, 300)}`,
  );
}

def(
  {
    id: 'register.lease',
    section: S,
    level: 'must',
    title: 'A key alone leases an address, or is 400 address_required',
    expected:
      '200 {"address","keys","grants","recovery"} with a new address and the key listed, or 400 address_required on a server that leases none',
  },
  async (t: T, ctx: Ctx) => {
    const a = TargetAgent.fresh(ctx.server);
    const res = await a.register(t, {});
    if (res.status === 400) {
      t.error(res, 400, 'address_required');
      return;
    }
    accountAnswer(t, res, a.token);
  },
);

def(
  {
    id: 'register.repeat',
    section: S,
    level: 'must',
    title: 'Repeating a register that succeeded returns the same result',
    expected: 'the same call again answers 200 account with the same address',
  },
  async (t: T, ctx: Ctx) => {
    await requireLeasing(ctx);
    const a = TargetAgent.fresh(ctx.server);
    const first = await a.register(t, {}, {}, 'first');
    accountAnswer(t, first, a.token, undefined, 'first');
    accountAnswer(t, await a.register(t, {}, {}, 'again'), a.token, first.json.address, 'again');
  },
);

def(
  {
    id: 'register.member-types',
    section: S,
    level: 'must',
    title: 'Register members must be strings',
    expected:
      '400 invalid, for a call signed by an agent the server knows, when key is a number, address is a number, code is true, or pairing is an object',
  },
  async (t: T, ctx: Ctx) => {
    // Signed by an agent the server knows, so the body is what is judged, not the key.
    const a = await ctx.agent('a');
    const cases: [string, Record<string, unknown>][] = [
      ['key a number', { key: 5 }],
      ['address a number', { address: 7 }],
      ['code true', { address: a.address, code: true }],
      ['pairing an object', { pairing: {} }],
    ];
    for (const [what, body] of cases) t.error(await a.register(t, body, {}, what), 400, 'invalid', what);
  },
);

def(
  {
    id: 'register.unknown-members',
    section: S,
    level: 'must',
    title: 'Members register does not define are ignored',
    expected: '200 account for a key alone with an extra member, on a server that leases',
  },
  async (t: T, ctx: Ctx) => {
    await requireLeasing(ctx);
    const a = TargetAgent.fresh(ctx.server);
    accountAnswer(t, await a.register(t, { 'x-conformance': { any: 'thing' } }), a.token);
  },
);

def(
  {
    id: 'register.hosted',
    section: S,
    level: 'must',
    title: "A name on a hosted domain is the agent's at once",
    expected:
      '200 account with exactly the address asked for, the key listed; the same call again gives the same result',
  },
  async (t: T, ctx: Ctx) => {
    const domain = requireHosted(ctx);
    const a = TargetAgent.fresh(ctx.server);
    const address = `${ctx.runId}-hosted@${domain}`;
    accountAnswer(t, await a.register(t, { address }, {}, 'first'), a.token, address, 'first');
    accountAnswer(t, await a.register(t, { address }, {}, 'again'), a.token, address, 'again');
  },
);

def(
  {
    id: 'register.not-recoverable-without-mailbox',
    section: S,
    level: 'must',
    title: 'A leased or hosted address cannot be taken over by registering another key',
    expected:
      "registering a new key with an address another agent holds, where the address has no mailbox, is refused (409 address_taken is the natural answer), and the holder's document does not list the new key",
  },
  async (t: T, ctx: Ctx) => {
    const holder = await ctx.agent('a');
    const thief = TargetAgent.fresh(ctx.server);
    const res = await thief.register(t, { address: holder.address });
    t.assert(
      res.status >= 400 && res.status < 500,
      `expected a 4xx refusal, got ${res.status} ${res.text.slice(0, 200)}`,
    );
    const { read } = await agentDocument(t, ctx, holder.address);
    t.assert(read && !lists(read.keys, thief.token), "the holder's document lists the new key");
    t.assert(read && lists(read.keys, holder.token), "the holder's own key is no longer listed");
  },
);

def(
  {
    id: 'register.address-taken-code',
    section: S,
    level: 'should',
    title: 'A held hosted or leased name is 409 address_taken',
    expected: '409 address_taken for a new key registering an address another agent holds',
  },
  async (t: T, ctx: Ctx) => {
    const holder = await ctx.agent('a');
    const res = await TargetAgent.fresh(ctx.server).register(t, { address: holder.address });
    t.error(res, 409, 'address_taken');
  },
);

def(
  {
    id: 'register.homed-elsewhere',
    section: S,
    level: 'must',
    title: 'An address whose domain names another server is 409 address_homed_elsewhere',
    expected:
      "409 address_homed_elsewhere with details.server the simulator's origin, for an address on the simulator's domain",
  },
  async (t: T, ctx: Ctx) => {
    const res = await TargetAgent.fresh(ctx.server).register(t, { address: ctx.peer.address('wants-in') });
    const err = t.error(res, 409, 'address_homed_elsewhere');
    t.assert(
      err.details?.server === ctx.peer.origin,
      `details.server is ${JSON.stringify(err.details?.server)}, expected ${ctx.peer.origin}`,
    );
  },
);

def(
  {
    id: 'register.no-server',
    section: S,
    level: 'must',
    title: 'An address whose domain names no server cannot be registered',
    expected:
      '409 address_homed_elsewhere with details.server null, for an address on a domain that resolves to no SIMON server',
  },
  async (t: T, ctx: Ctx) => {
    const res = await TargetAgent.fresh(ctx.server).register(t, { address: `x@${ctx.opts.unresolvableDomain}` });
    const err = t.error(res, 409, 'address_homed_elsewhere');
    t.assert(err.details?.server === null, `details.server is ${JSON.stringify(err.details?.server)}, expected null`);
  },
);

/** An add-key call, signed by `signer`, for `newKey` with this proof. */
function addKey(t: T, signer: TargetAgent, newKey: crypto.KeyObject, proof: string | undefined, label: string) {
  const body: Record<string, unknown> = { key: keyToken(newKey) };
  if (proof !== undefined) body.proof = proof;
  return signer.call(t, 'POST', '/simon/keys', JSON.stringify(body), {}, label);
}

def(
  {
    id: 'keys.add-key',
    section: 'CLIENT keys',
    level: 'must',
    title: "An agent adds a key with the new key's proof",
    expected:
      '200 account listing the new key, for POST /simon/keys {"key","proof"} signed by an existing key, proof over SIMON-ADD-KEY\\n<address>\\n<key>; the same call again gives the same result; the new key then signs requests',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('keys');
    const k2 = crypto.generateKeyPairSync('ed25519').privateKey;
    const proof = sign(k2, addKeyProofString(a.address, keyToken(k2)));
    accountAnswer(t, await addKey(t, a, k2, proof, 'add a key'), keyToken(k2), a.address, 'add a key');
    accountAnswer(t, await addKey(t, a, k2, proof, 'again'), keyToken(k2), a.address, 'the same call again');
    const res = await a.call(t, 'GET', '/simon/sync?limit=1', undefined, { key: k2 }, 'signed by the new key');
    t.status(res, 200, 'a request signed by the new key');
  },
);

def(
  {
    id: 'keys.add-key-bad-proof',
    section: 'CLIENT keys, CLIENT errors',
    level: 'must',
    title: 'An add-key proof that does not verify is 401 bad_proof',
    expected: '401 bad_proof for a proof over another address, and for a proof signed by a different key',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('keys');
    const k2 = crypto.generateKeyPairSync('ed25519').privateKey;
    const other = crypto.generateKeyPairSync('ed25519').privateKey;
    const cases: [string, string][] = [
      ['a proof over another address', sign(k2, addKeyProofString(`other-${a.address}`, keyToken(k2)))],
      ['a proof by another key', sign(other, addKeyProofString(a.address, keyToken(k2)))],
    ];
    for (const [what, proof] of cases) t.error(await addKey(t, a, k2, proof, what), 401, 'bad_proof', what);
  },
);

def(
  {
    id: 'keys.add-key-no-proof',
    section: 'CLIENT keys, CLIENT errors',
    level: 'must',
    title: 'Adding a key without a proof is 401 bad_proof',
    expected: '401 bad_proof for POST /simon/keys {"key"} signed by an existing key of an agent, with no proof',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('keys');
    t.error(
      await addKey(t, a, crypto.generateKeyPairSync('ed25519').privateKey, undefined, 'no proof'),
      401,
      'bad_proof',
    );
  },
);

def(
  {
    id: 'keys.too-many-keys',
    section: 'CLIENT keys, PROTOCOL 4',
    level: 'must',
    title: 'An agent cannot hold more keys than its document may list',
    expected:
      'adding keys one by one is refused with 400 too_many_keys before the agent holds 33 (a document lists at most 32 keys)',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('many-keys');
    for (let held = 1; held <= 32; held++) {
      const k = crypto.generateKeyPairSync('ed25519').privateKey;
      const s = t.scratch();
      const res = await addKey(s, a, k, sign(k, addKeyProofString(a.address, keyToken(k))), `key ${held + 1}`);
      if (res.status === 200) continue;
      t.adopt(s.exchanges);
      t.error(res, 400, 'too_many_keys', `the key that would make ${held + 1}`);
      return;
    }
    t.fail('33 keys were accepted; an agent document lists at most 32');
  },
);

def(
  {
    id: 'register.ml-dsa',
    section: `${S}, PROTOCOL 2.3`,
    level: 'must',
    title: 'An agent may hold an ML-DSA-65 key',
    expected:
      'registering with an ml-dsa-65 key succeeds, its document lists the key, and requests it signs answer 200',
  },
  async (t: T, ctx: Ctx) => {
    const m = await ctx.agent('mldsa', 'ml-dsa-65');
    const { read } = await agentDocument(t, ctx, m.address);
    t.assert(read && lists(read.keys, m.token), 'the agent document does not list the ml-dsa-65 key');
    t.status(await m.sync(t, 'limit=1'), 200, 'a request signed with ml-dsa-65');
  },
);

/** A paired agent whose principal is a key, registered by leasing (or on the hosted domain). */
export interface Paired {
  agent: TargetAgent;
  principal: crypto.KeyObject;
  for: string;
}

/** Register with `for`; on 202 pairing_required, sign the pairing for the address given and repeat. */
async function pairByLease(t: T, ctx: Ctx): Promise<{ first: Res; second?: Res; paired?: Paired }> {
  const agent = TargetAgent.fresh(ctx.server);
  const principal = crypto.generateKeyPairSync('ed25519').privateKey;
  const forValue = `simon-key:${keyToken(principal)}`;
  const first = await agent.register(t, { for: forValue }, {}, 'register with for, no pairing');
  if (first.status !== 202 || typeof first.json?.address !== 'string') return { first };
  const pairing = signPairing(principal, first.json.address, forValue);
  const second = await agent.register(t, { for: forValue, pairing }, {}, 'the same call with the pairing');
  if (second.status === 200) agent.address = second.json.address;
  return { first, second, paired: second.status === 200 ? { agent, principal, for: forValue } : undefined };
}

/** A new paired agent whose principal is a key: leased when the server leases, else on the hosted domain. */
async function registerPaired(t: T, ctx: Ctx, name: string): Promise<Paired> {
  if (await leasing(ctx)) {
    const { paired, first, second } = await pairByLease(t, ctx);
    if (paired) return paired;
    throw new Prerequisite(`pairing by lease answered ${first.status}${second ? ` then ${second.status}` : ''}`);
  }
  const domain = requireHosted(ctx);
  const agent = TargetAgent.fresh(ctx.server);
  const principal = crypto.generateKeyPairSync('ed25519').privateKey;
  const forValue = `simon-key:${keyToken(principal)}`;
  const address = `${ctx.runId}-${name}@${domain}`;
  const res = await agent.register(t, { address, for: forValue, pairing: signPairing(principal, address, forValue) });
  if (res.status !== 200) throw new Prerequisite(`registering a paired agent answered ${res.status}`);
  agent.address = address;
  return { agent, principal, for: forValue };
}

export const pairedAgent = (ctx: Ctx): Promise<Paired> =>
  ctx.once('a paired agent', t => registerPaired(t, ctx, 'paired'));

def(
  {
    id: 'register.pairing-required',
    section: S,
    level: 'must',
    title: 'Pairing a leased address goes through pairing_required',
    expected:
      'register {"key","for"} with a simon-key: principal answers 202 {"status":"pairing_required","address"}; the same call with "pairing", the principal\'s signature over SIMON-PAIR\\n<address>\\n<for>, answers 200 account at that address',
  },
  async (t: T, ctx: Ctx) => {
    await requireLeasing(ctx);
    const { first, second } = await pairByLease(t, ctx);
    t.status(first, 202, 'register with for and no pairing');
    t.assert(first.json?.status === 'pairing_required', `status is ${JSON.stringify(first.json?.status)}`);
    t.assert(isV1Address(first.json?.address), `address is ${JSON.stringify(first.json?.address)}`);
    t.assert(second, 'no second call was made');
    t.status(second, 200, 'the same call with the pairing');
    t.assert(
      second.json?.address === first.json.address && Array.isArray(second.json?.keys),
      `answered ${second.text.slice(0, 200)}`,
    );
  },
);

def(
  {
    id: 'register.paired-document',
    section: `${S}, PROTOCOL 4`,
    level: 'must',
    title: "A paired agent's document says paired, and never who",
    expected: 'kind is "paired", and nothing in the document names the principal\'s key',
  },
  async (t: T, ctx: Ctx) => {
    const p = await pairedAgent(ctx);
    const { res, read } = await agentDocument(t, ctx, p.agent.address);
    t.status(res, 200);
    t.assert(read?.kind === 'paired', `kind is ${JSON.stringify(res.json?.kind)}`);
    const principalToken = p.for.slice('simon-key:'.length);
    t.assert(!res.text.includes(principalToken), "the document contains the principal's key");
  },
);

def(
  {
    id: 'register.pairing-bad-proof',
    section: `${S}, CLIENT errors`,
    level: 'must',
    title: 'A pairing that does not verify is 401 bad_proof',
    expected: '401 bad_proof for register with for and a pairing signed for another address',
  },
  async (t: T, ctx: Ctx) => {
    const agent = TargetAgent.fresh(ctx.server);
    const principal = crypto.generateKeyPairSync('ed25519').privateKey;
    const forValue = `simon-key:${keyToken(principal)}`;
    const body: Record<string, unknown> = {
      for: forValue,
      pairing: signPairing(principal, 'someone@else.example', forValue),
    };
    if (ctx.opts.hostedDomain) body.address = `${ctx.runId}-badpair@${ctx.opts.hostedDomain}`;
    else await requireLeasing(ctx);
    t.error(await agent.register(t, body), 401, 'bad_proof');
  },
);

def(
  {
    id: 'register.pairing-hosted',
    section: S,
    level: 'must',
    title: 'A hosted address pairs in one call',
    expected:
      'register {"key","address","for","pairing"} on a hosted domain answers 200 account, and the document says paired',
  },
  async (t: T, ctx: Ctx) => {
    const domain = requireHosted(ctx);
    const agent = TargetAgent.fresh(ctx.server);
    const principal = crypto.generateKeyPairSync('ed25519').privateKey;
    const forValue = `simon-key:${keyToken(principal)}`;
    const address = `${ctx.runId}-pairedhosted@${domain}`;
    accountAnswer(
      t,
      await agent.register(t, { address, for: forValue, pairing: signPairing(principal, address, forValue) }),
      agent.token,
      address,
    );
    const { read } = await agentDocument(t, ctx, address);
    t.assert(read?.kind === 'paired', `kind is ${JSON.stringify(read?.kind)}`);
  },
);

// The code flow, only when the operator gives a way to read codes.

const codeFlow = (ctx: Ctx) =>
  ctx.once('the code flow', async t => {
    const address = ctx.opts.codeAddress;
    if (!ctx.opts.codeCommand || !address) throw new Prerequisite('no --code-command and --code-address were given');
    const agent = TargetAgent.fresh(ctx.server);
    const sent = await agent.register(t, { address }, {}, 'register an address with a mailbox');
    return { agent, address, sent };
  });

/** A wrong code of the same shape as the right one. */
const wrongCode = (code: string) =>
  code.slice(0, -1) +
  (/\d/.test(code.at(-1)!) ? String((Number(code.at(-1)) + 1) % 10) : code.at(-1) === 'a' ? 'b' : 'a');

def(
  {
    id: 'register.code',
    section: S,
    level: 'must',
    title: 'An address with a mailbox is bound by the code sent there',
    expected:
      'register {"key","address"} answers 202 {"status":"code_sent","address"}; the same call with a wrong code answers 422 wrong_code; with the code the operator\'s command printed, 200 account',
  },
  async (t: T, ctx: Ctx) => {
    const { agent, address, sent } = await codeFlow(ctx);
    t.adopt(ctx.setupExchanges.filter(e => e.label === 'register an address with a mailbox'));
    t.status(sent, 202, 'register the address');
    t.assert(
      sent.json?.status === 'code_sent' && sent.json?.address === address,
      `answered ${sent.text.slice(0, 200)}`,
    );
    const code = await ctx.code(address);
    t.error(await agent.register(t, { address, code: wrongCode(code) }, {}, 'a wrong code'), 422, 'wrong_code');
    accountAnswer(t, await agent.register(t, { address, code }, {}, 'the code'), agent.token, address, 'the code');
    agent.address = address;
    bound.set(ctx, agent);
  },
);

/** The agent the code flow bound, once register.code has run: its key holds the address. */
const bound = new WeakMap<Ctx, TargetAgent>();
/** A key recovery replaced, for requests.key-revoked. */
const recovered = new WeakMap<Ctx, TargetAgent>();

/** A new key asks for the address's code and hands it back: both answers, and the code. */
async function claimByCode(t: T, ctx: Ctx, address: string, what: string) {
  const fresh = TargetAgent.fresh(ctx.server);
  const sent = await fresh.recover(t, { address }, {}, `${what}: ask for a code`);
  t.status(sent, 202, `${what}: a new key asks for the code`);
  const code = await ctx.code(address);
  const answer = await fresh.recover(t, { address, code }, {}, `${what}: the code`);
  return { fresh, code, answer };
}

/** Whether an answer is 202 recovery_pending for `address`, with completesAt a timestamp after `now`. */
function isPending(res: Res, address: string, now: number) {
  const at = parseTimestamp(res.json?.completesAt);
  return (
    res.status === 202 &&
    res.json?.status === 'recovery_pending' &&
    res.json?.address === address &&
    at !== null &&
    at > now - 2000
  );
}

/** The bound agent's document: whether it still lists its own key valid and not `other`. */
async function unchanged(t: T, ctx: Ctx, holder: TargetAgent, other: TargetAgent) {
  const { read } = await agentDocument(t, ctx, holder.address);
  const own = read?.keys.find(k => k.key === holder.token);
  return !!own && validAt(own, new Date(ctx.now())) && !lists(read?.keys, other.token);
}

const bindFirst = (ctx: Ctx, t: T) => {
  const holder = bound.get(ctx);
  if (!holder) t.skip('the code flow did not bind a first key (see register.code)');
  return holder;
};

def(
  {
    id: 'register.recovery-pending',
    section: R,
    level: 'should',
    title: 'Recovery by code waits while the agent still holds a valid key, and the agent is told',
    expected:
      '202 {"status":"recovery_pending","address","completesAt"} for POST /simon/recovery with a new key handing back the code while the agent holds a valid key; its document is unchanged meanwhile, and its inbox gets a message from the server itself',
  },
  async (t: T, ctx: Ctx) => {
    const holder = bindFirst(ctx, t);
    const before = ctx.now();
    const { fresh, answer } = await claimByCode(t, ctx, holder.address, 'a second key');
    if (answer.status === 200) recovered.set(ctx, holder);
    else pendingClaim.set(ctx, fresh);
    t.assert(
      isPending(answer, holder.address, before),
      `expected 202 recovery_pending with completesAt, got ${answer.status} ${answer.text.slice(0, 200)}`,
    );
    t.assert(await unchanged(t, ctx, holder, fresh), 'the document changed while the recovery waits');
    const state = await holder.call(t, 'GET', '/simon/account');
    t.status(state, 200);
    t.assert(
      state.json?.recovery?.completesAt === answer.json.completesAt &&
        typeof state.json.recovery.cancellable === 'boolean',
      'the account does not show the pending recovery',
    );
    const told = (await readSync(t, holder, "the holder's inbox")).some(
      e => e.carrier === ctx.origin && e.message.from !== holder.address && Date.parse(e.receivedAt) >= before - 5000,
    );
    t.assert(told, 'no message from the server itself reached the agent');
  },
);

/** The new key whose recovery is waiting, for register.cancel-recovery. */
const pendingClaim = new WeakMap<Ctx, TargetAgent>();

const requirePending = (ctx: Ctx, t: T) => {
  const holder = bindFirst(ctx, t);
  const fresh = pendingClaim.get(ctx);
  if (!fresh) t.skip('no recovery was waiting (see register.recovery-pending)');
  return { holder, fresh };
};

def(
  {
    id: 'register.recovery-status',
    section: R,
    level: 'must',
    title: "An agent's key reads a waiting recovery; no other key can",
    expected:
      'GET /simon/recovery signed by the key the agent holds answers 200 {"recovery":{"completesAt","cancellable"}}, completesAt a timestamp and cancellable a boolean; signed by a key the server does not know, 401 unknown_key',
  },
  async (t: T, ctx: Ctx) => {
    const { holder } = requirePending(ctx, t);
    const res = await holder.call(t, 'GET', '/simon/recovery', undefined, {}, 'read the recovery');
    t.status(res, 200, 'read the recovery');
    const r = res.json?.recovery;
    t.assert('recovery' in (res.json ?? {}), `answered ${res.text.slice(0, 200)}`);
    t.assert(r && parseTimestamp(r.completesAt) !== null, `recovery is ${JSON.stringify(r)}`);
    t.assert(typeof r.cancellable === 'boolean', `cancellable is ${JSON.stringify(r.cancellable)}, not a boolean`);
    const stranger = TargetAgent.fresh(ctx.server);
    const asked = await stranger.call(
      t,
      'GET',
      '/simon/recovery',
      undefined,
      { agent: holder.address },
      'a stranger asks',
    );
    t.error(asked, 401, 'unknown_key', 'a stranger reads the recovery');
  },
);

def(
  {
    id: 'register.recovery-cancellable',
    section: `${R}, CLIENT recommended host practice`,
    level: 'should',
    title: 'A key the agent held before a recovery started is told it may cancel it',
    expected:
      'GET /simon/recovery signed by the key the agent held before the recovery started says cancellable true, as the recommended practice lets such a key cancel (who may cancel is host policy)',
  },
  async (t: T, ctx: Ctx) => {
    const { holder } = requirePending(ctx, t);
    const res = await holder.call(t, 'GET', '/simon/recovery', undefined, {}, 'read the recovery');
    t.status(res, 200, 'read the recovery');
    t.assert(
      res.json?.recovery?.cancellable === true,
      `cancellable is ${JSON.stringify(res.json?.recovery?.cancellable)} for a key held before the recovery started`,
    );
  },
);

def(
  {
    id: 'register.recovery-hidden',
    section: R,
    level: 'must',
    title: 'No answer tells a stranger whether an address is being recovered',
    expected:
      'while a recovery waits, POST /simon/recovery from a new key asking for a code answers 202 code_sent and a wrong code then 422 wrong_code, as when none waits; a wrong cancel code for the address answers 422 wrong_code with the same body as one for an address with no recovery waiting',
  },
  async (t: T, ctx: Ctx) => {
    const { holder } = requirePending(ctx, t);
    const probe = TargetAgent.fresh(ctx.server);
    const asked = await probe.recover(t, { address: holder.address }, {}, 'a stranger asks for a code');
    t.status(asked, 202, 'a stranger asks for a code while a recovery waits');
    t.assert(asked.json?.status === 'code_sent', `answered ${asked.text.slice(0, 200)}`);
    t.error(await probe.recover(t, { address: holder.address, code: '00000000' }, {}, 'a guess'), 422, 'wrong_code');
    const guess = crypto.randomBytes(16).toString('base64url');
    const waiting = await probe.cancelRecovery(
      t,
      { address: holder.address, cancelCode: guess },
      {},
      'a wrong cancel code',
    );
    const none = await probe.cancelRecovery(
      t,
      { address: `${ctx.runId}-nobody@${await ctx.domain()}`, cancelCode: guess },
      {},
      'a cancel code for an address with no recovery',
    );
    t.error(waiting, 422, 'wrong_code', 'a wrong cancel code');
    t.error(none, 422, 'wrong_code', 'a cancel code for an address with no recovery');
    t.assert(waiting.text === none.text, `the two answers differ: ${waiting.text} / ${none.text}`);
  },
);

def(
  {
    id: 'register.cancel-recovery',
    section: C,
    level: 'must',
    title: 'An authorised agent key cancels a waiting recovery',
    expected:
      'POST /simon/recovery/cancel {} signed by a key the account permits answers 200 {"status":"cancelled","address"}; the waiting key then cannot complete the recovery with its code, and the document lists only the old key',
  },
  async (t: T, ctx: Ctx) => {
    const holder = bindFirst(ctx, t);
    const fresh = pendingClaim.get(ctx);
    if (!fresh) t.skip('no recovery was waiting (see register.recovery-pending)');
    const res = await holder.call(t, 'POST', '/simon/recovery/cancel', '{}', {}, 'cancel the recovery');
    if (res.status === 409) {
      t.error(res, 409, 'recovery_not_cancellable');
      t.skip('host policy refuses cancellation by this key');
    }
    t.status(res, 200, 'cancel');
    t.assert(
      res.json?.status === 'cancelled' && res.json.address === holder.address,
      `cancel answered ${res.text.slice(0, 200)}`,
    );
    t.error(await holder.call(t, 'POST', '/simon/recovery/cancel', '{}'), 404, 'not_found', 'cancel again');
    const again = await fresh.recover(
      t,
      { address: holder.address, code: await ctx.code(holder.address) },
      {},
      'the waiting key tries again',
    );
    t.assert(
      again.status !== 200,
      `the waiting key completed the recovery after it was cancelled: ${again.text.slice(0, 200)}`,
    );
    t.assert(await unchanged(t, ctx, holder, fresh), 'the document changed after the recovery was cancelled');
  },
);

def(
  {
    id: 'register.recovery',
    section: R,
    level: 'must',
    title: 'Recovery by code replaces every old key',
    expected:
      'POST /simon/recovery with the new key and code gets 200 account {address,keys,grants,recovery} without a status member, or 202 recovery_pending and then 200 account when it repeats the recovery call after completesAt (waited for when within the recovery wait); the old key is then marked revoked in the document',
  },
  async (t: T, ctx: Ctx) => {
    const old = bindFirst(ctx, t);
    const address = old.address;
    if (recovered.has(ctx)) t.skip('the server recovered at once in register.recovery-pending');
    const { fresh, code, answer } = await claimByCode(t, ctx, address, 'a third key');
    let done = answer;
    if (answer.status === 202) {
      t.assert(isPending(answer, address, ctx.now() - 60_000), `answered ${answer.text.slice(0, 200)}`);
      const wait = Date.parse(answer.json.completesAt) - ctx.now() + 1000;
      if (wait > ctx.opts.recoveryWaitMs) {
        t.skip(
          `the recovery completes at ${answer.json.completesAt}, beyond the recovery wait (${ctx.opts.recoveryWaitMs / 1000} s); run the server with a shorter wait (the basic server: SIMON_RECOVERY_WAIT=5)`,
        );
      }
      await sleep(Math.max(0, wait));
      done = await fresh.recover(t, { address, code }, {}, 'the code again, after completesAt');
    }
    accountAnswer(t, done, fresh.token, address, 'the recovery');
    fresh.address = address;
    holding.set(ctx, fresh);
    const { read } = await agentDocument(t, ctx, address);
    t.assert(read, 'the agent document is unreadable after recovery');
    const oldEntry = read.keys.find(k => k.key === old.token);
    t.assert(
      !oldEntry || !validAt(oldEntry, new Date(ctx.now())),
      `the old key is still valid: ${JSON.stringify(oldEntry)}`,
    );
    recovered.set(ctx, old);
  },
);

/** The key holding the code flow's address once register.recovery completed, for the checks after it. */
const holding = new WeakMap<Ctx, TargetAgent>();

/** A recovery register.cancel-once started and could not cancel, for register.cancel-code. */
const uncancelled = new WeakMap<Ctx, { address: string; claim: TargetAgent; code: string }>();

def(
  {
    id: 'register.cancel-once',
    section: `${C}, CLIENT recommended host practice`,
    level: 'should',
    title: 'A key cancels a recovery once in 30 days',
    expected:
      'a recovery started after register.cancel-recovery cancelled one by key answers 409 recovery_not_cancellable to a cancel by the key now holding the agent, and GET /simon/recovery says cancellable false',
  },
  async (t: T, ctx: Ctx) => {
    const holder = holding.get(ctx);
    if (!holder || !ctx.opts.codeCommand) t.skip('needs register.cancel-recovery and register.recovery to have run');
    const { fresh, code, answer } = await claimByCode(t, ctx, holder.address, 'a fourth key');
    if (answer.status !== 202) t.skip(`the recovery did not wait: ${answer.status}`);
    const res = await holder.call(t, 'POST', '/simon/recovery/cancel', '{}', {}, 'cancel by key');
    // Only a recovery the key could not cancel is still waiting for register.cancel-code; a host whose policy
    // let the key cancel it leaves none, and that check then skips rather than fails.
    if (res.status === 409) uncancelled.set(ctx, { address: holder.address, claim: fresh, code });
    t.error(res, 409, 'recovery_not_cancellable', 'a second cancel by key within 30 days');
    const status = await holder.call(t, 'GET', '/simon/recovery', undefined, {}, 'read it');
    t.assert(status.json?.recovery?.cancellable === false, `recovery is ${JSON.stringify(status.json?.recovery)}`);
  },
);

def(
  {
    id: 'register.cancel-code',
    section: C,
    level: 'must',
    title: 'The cancel code sent with the news of a recovery cancels it, whoever signs; once',
    expected:
      'POST /simon/recovery/cancel {"address","cancelCode"} with the cancel code the operator\'s command printed, signed by a key the server never saw, answers 200 {"status":"cancelled","address"}; the same call again answers 422 wrong_code; the waiting key cannot complete the recovery after it',
  },
  async (t: T, ctx: Ctx) => {
    const waiting = uncancelled.get(ctx);
    if (!waiting) t.skip('no recovery is waiting (see register.cancel-once)');
    const cancelCode = await ctx.cancelCode(waiting.address);
    const stranger = TargetAgent.fresh(ctx.server);
    const res = await stranger.cancelRecovery(t, { address: waiting.address, cancelCode }, {}, 'the cancel code');
    t.status(res, 200, 'the cancel code');
    t.assert(
      res.json?.status === 'cancelled' && res.json?.address === waiting.address,
      `answered ${res.text.slice(0, 200)}`,
    );
    const again = await stranger.cancelRecovery(
      t,
      { address: waiting.address, cancelCode },
      {},
      'the cancel code again',
    );
    t.error(again, 422, 'wrong_code', 'a cancel code for a recovery that ended');
    const late = await waiting.claim.recover(t, { address: waiting.address, code: waiting.code }, {}, 'the claim');
    t.assert(late.status !== 200, `the cancelled recovery completed: ${late.text.slice(0, 200)}`);
  },
);

/** A paired agent, recovered by its key principal in register.principal-recovery, and the key it replaced. */
const rescued = new WeakMap<Ctx, { p: Paired; fresh: TargetAgent }>();

def(
  {
    id: 'register.principal-recovery',
    section: R,
    level: 'must',
    title: "A key principal recovers its agent at once, to a key of the principal's choosing",
    expected:
      'POST /simon/recovery {"address","key","at","recover"} signed by the new key, recover the principal\'s signature over SIMON-RECOVER\\n<address>\\n<key>\\n<at>, answers 200 account {address,keys,grants,recovery} without a status member, listing the new key, the old key revoked; the old key is then 401 key_revoked, and the same call again answers alike',
  },
  async (t: T, ctx: Ctx) => {
    const p = await registerPaired(t, ctx, 'rescued');
    const fresh = TargetAgent.fresh(ctx.server);
    const at = new Date(ctx.now()).toISOString();
    const recover = signRecovery(p.principal, p.agent.address, fresh.token, at);
    const body = { address: p.agent.address, at, recover };
    const res = await fresh.recover(t, body, {}, "the principal's recovery");
    accountAnswer(t, res, fresh.token, p.agent.address, "the principal's recovery");
    const old = res.json?.keys?.find((k: { key: string }) => k.key === p.agent.token);
    t.assert(old && old.revoked !== null, `the old key is not revoked: ${JSON.stringify(old)}`);
    t.error(await p.agent.sync(t, 'limit=1', 'the old key'), 401, 'key_revoked');
    accountAnswer(t, await fresh.recover(t, body, {}, 'the same call again'), fresh.token, p.agent.address, 'again');
    fresh.address = p.agent.address;
    rescued.set(ctx, { p, fresh });
  },
);

def(
  {
    id: 'register.principal-recovery-refused',
    section: R,
    level: 'must',
    title: "A principal's recovery that is stale, forged or brings back a revoked key is refused",
    expected:
      '400 invalid with details.field "at" for an at 25 hours old and one 10 minutes ahead; 401 bad_proof for a recovery signed by another key; 409 key_in_use for a recovery to a key the agent held and that is now revoked',
  },
  async (t: T, ctx: Ctx) => {
    const done = rescued.get(ctx);
    if (!done) t.skip('needs register.principal-recovery');
    const { p } = done;
    const next = TargetAgent.fresh(ctx.server);
    const address = p.agent.address;
    for (const [what, ms] of [
      ['25 hours old', -25 * 3600_000],
      ['10 minutes ahead', 10 * 60_000],
    ] as const) {
      const at = new Date(ctx.now() + ms).toISOString();
      const res = await next.recover(
        t,
        { address, at, recover: signRecovery(p.principal, address, next.token, at) },
        {},
        what,
      );
      const err = t.error(res, 400, 'invalid', `an at ${what}`);
      t.assert(err.details?.field === 'at', `details.field is ${JSON.stringify(err.details?.field)}`);
    }
    const at = new Date(ctx.now()).toISOString();
    const other = crypto.generateKeyPairSync('ed25519').privateKey;
    const forged = await next.recover(
      t,
      { address, at, recover: signRecovery(other, address, next.token, at) },
      {},
      'forged',
    );
    t.error(forged, 401, 'bad_proof', 'a recovery signed by another key');
    const back = await p.agent.recover(
      t,
      { address, at, recover: signRecovery(p.principal, address, p.agent.token, at) },
      {},
      'the revoked key back',
    );
    t.error(back, 409, 'key_in_use', 'a recovery to a revoked key');
  },
);

def(
  {
    id: 'requests.key-revoked',
    section: 'PROTOCOL 8',
    level: 'must',
    title: 'A key no longer valid is 401 key_revoked',
    expected: '401 key_revoked (with details.serverTime) for a request signed by a key that recovery replaced',
  },
  async (t: T, ctx: Ctx) => {
    const old = recovered.get(ctx);
    if (!old)
      t.skip('needs a key revoked by recovery (register.recovery, which needs --code-command and --code-address)');
    const err = t.error(await old.sync(t, 'limit=1'), 401, 'key_revoked');
    t.assert(Number.isInteger(err.details?.serverTime), 'the 401 has no integer details.serverTime');
  },
);

def(
  {
    id: 'register.unpair',
    section: 'PROTOCOL 2.2, CLIENT Unpairing',
    level: 'must',
    title: "A key principal's unpairing retires its agent's address, whatever the agent's keys say",
    expected:
      'POST /simon/unpair {"address","unpairing"} signed by a key the server never saw, unpair the principal\'s signature over SIMON-UNPAIR\\n<address>\\n<for>, answers 200 {"status":"retired","address"}; the agent document is then 404 or a valid retired document, a request signed by the agent\'s key is 401 key_revoked, and the same call again answers 200 retired',
  },
  async (t: T, ctx: Ctx) => {
    const p = await registerPaired(t, ctx, 'unpaired');
    const unpair = signUnpairing(p.principal, p.agent.address, p.for);
    const stranger = TargetAgent.fresh(ctx.server);
    for (const when of ['unpair', 'unpair again']) {
      const res = await stranger.call(
        t,
        'POST',
        '/simon/unpair',
        JSON.stringify({ address: p.agent.address, unpairing: unpair }),
        {},
        when,
      );
      t.status(res, 200, when);
      t.assert(
        res.json?.status === 'retired' && res.json?.address === p.agent.address,
        `${when}: answered ${res.text.slice(0, 200)}`,
      );
    }
    const { res: doc, read } = await agentDocument(t, ctx, p.agent.address, 'the agent document after unpairing');
    if (doc.status === 404) t.error(doc, 404, 'not_found', 'the host keeps retirement private');
    else {
      t.status(doc, 200, 'the optional retired document');
      t.assert(read?.retired !== undefined, 'the retired document is unreadable or has no retirement time');
      t.assert(
        read.unpairing !== undefined && verifyUnpairing(p.agent.address, p.for, read.unpairing),
        'the retired document does not carry the unpairing that retired it',
      );
      t.assert(
        read.keys.every(k => k.revoked !== null && Date.parse(k.revoked) <= Date.parse(read.retired!)),
        'the retired document lists a key valid after retirement',
      );
    }
    t.error(await p.agent.sync(t, 'limit=1', "the agent's key after unpairing"), 401, 'key_revoked');
  },
);

def(
  {
    id: 'register.unpair-bad-proof',
    section: 'PROTOCOL 2.2, CLIENT Unpairing, CLIENT errors',
    level: 'must',
    title: 'An unpairing that does not verify is 401 bad_proof, and retires nothing',
    expected:
      '401 bad_proof for POST /simon/unpair with an unpairing signed by another key, and for a pairing signature offered as an unpairing; the agent document is still served',
  },
  async (t: T, ctx: Ctx) => {
    const p = await registerPaired(t, ctx, 'not-unpaired');
    const stranger = TargetAgent.fresh(ctx.server);
    const other = crypto.generateKeyPairSync('ed25519').privateKey;
    for (const [what, unpair] of [
      ['an unpairing by another key', signUnpairing(other, p.agent.address, p.for)],
      ['the pairing signature', signPairing(p.principal, p.agent.address, p.for)],
    ] as const) {
      t.error(
        await stranger.call(
          t,
          'POST',
          '/simon/unpair',
          JSON.stringify({ address: p.agent.address, unpairing: unpair }),
          {},
          what,
        ),
        401,
        'bad_proof',
        what,
      );
    }
    const { res: doc, read } = await agentDocument(t, ctx, p.agent.address, 'the agent document');
    t.status(doc, 200, 'the agent document is still served');
    t.assert(read && read.retired === undefined, 'the agent document is still an agent document, not retired');
  },
);
