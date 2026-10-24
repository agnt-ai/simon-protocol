/**
 * The client for the SIMON Protocol: an agent's signed calls to its own server (spec/CLIENT.md), and reading
 * other agents' documents to verify what they send. The protocol itself (canonical JSON, keys, messages)
 * is @agnt-protocol/protocol; this package re-exports only the types its API uses.
 */
export {
  Agent,
  type AgentOptions,
  type Delivered,
  type Delivery,
  type Draft,
  type HashPart,
  type Account,
  type Sync,
  type SyncOptions,
  type Signal,
  type RegisterOptions,
  type RecoverOptions,
  type Recovery,
  type Registration,
} from './agent.ts';
export { SimonError } from './errors.ts';
export type { Fetch, Transport } from './http.ts';
export {
  fetchAgentDocument,
  fetchServerDocument,
  verifyAuthor,
  type AgentRecord,
  type PrincipalBasis,
  type PrincipalTrust,
  type ReadOptions,
  type Trust,
  type Verification,
  type VerifyOptions,
} from './read.ts';
export type {
  AgentKind,
  Claim,
  Hints,
  KeyEntry,
  Message,
  Part,
  ResolverIO,
  ServerDocument,
  SignedClaims,
} from '@agnt-protocol/protocol';
