/**
 * Who reads a published message, and whether its audience admits them (publishing profile, section 1).
 *
 * A reader proves who it is the way an author does: it signs the request with a key of its own agent
 * document and names itself in `simon-agent` (section 8). A request that is not signed, or whose signature
 * fails, asks as nobody in particular, and is answered exactly as one, so a refusal tells nothing about
 * the message.
 *
 * A message with no `audience` header is for anyone. One with a label is for whoever the extensions'
 * `admitsReader` chain admits; with no extension deciding, for no one but its author.
 */
import { header, VERSION, WireError, type AnyMessage, type Message } from '@agnt-sdk/simon-protocol';
import { authenticateReader, isAgentSigned } from './auth.ts';
import type { Context } from './context.ts';
import type { Request } from './http.ts';

/** Who asks: the reader that signed, null for nobody in particular. */
export interface Asker {
  reader(): Promise<string | null>;
}

const NOBODY: Asker = { reader: async () => null };

/** An asker already known: an agent here whose own signature this server checked. */
export const asReader = (address: string): Asker => ({ reader: async () => address });

/**
 * Who asks, settled before anything is looked up for the request: a request naming `simon-agent` is
 * authenticated at once, its reader's document fetched and charged to the client, whatever it asks for and
 * whether or not anything matches, so neither the answer nor the fetches it makes tell which ids, feeds or
 * parts hold audience-limited posts (publishing profile, section 1).
 */
export async function askerOf(ctx: Context, req: Request): Promise<Asker> {
  if (!isAgentSigned(req)) return NOBODY;
  try {
    return asReader(await authenticateReader(ctx, req));
  } catch (e) {
    // A signature that fails asks as nobody, and so does a reader whose document could not be looked up (a
    // client out of lookups, a pool that is full), as the spec's reader whose document cannot be read for now.
    if (e instanceof WireError && [401, 429, 503].includes(e.status)) return NOBODY;
    throw e;
  }
}

/** The audience label a published version 2 message carries, or null for anyone. */
export const audienceOf = (m: AnyMessage) => (m.v === VERSION ? header(m as Message, 'audience') : null);

/** Whether a published message written here may be shown to this asker. */
export async function mayRead(ctx: Context, m: AnyMessage, asker: Asker): Promise<boolean> {
  const audience = audienceOf(m);
  if (audience === null) return true;
  const reader = await asker.reader();
  if (reader === m.from) return true;
  return (await ctx.hooks.admitsReader({ message: m, audience, reader })) === 'admit';
}
