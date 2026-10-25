/**
 * The listing of the person an agent speaks for, and the page behind the link sent to a person after
 * their agent's keys were replaced (GET only shows the question, since mail scanners follow links).
 */
import { z } from 'zod';
import type { Ctx } from '../../../context.ts';
import { WireError } from '../../../lib/errors.ts';
import { clientKey, spend } from '../../../lib/rate.ts';
import { esc, htmlPage, pageShell } from '../../../http/pages.ts';
import type { Agent } from '@agnt-sdk/simon-server';
import { agent, anyone, defineRoute, type ApiRoute, type Caller } from '../../../http/route.ts';
import type { Directory } from '../index.ts';
import { listingView } from '../people.ts';
import { Listing, ListingPatch } from '../schemas.ts';

export function personRoutes(d: Directory, reserved: Caller<Agent>): ApiRoute[] {
  const tag = 'Directory';
  return [
    defineRoute({
      method: 'GET',
      path: '/api/listing',
      operationId: 'getListing',
      tag,
      summary: 'The listing of the person this agent speaks for',
      caller: agent,
      response: Listing,
      handle: async ({ caller }) => listingView((await d.people.personOf(caller)).person.listing),
    }),
    defineRoute({
      method: 'PATCH',
      path: '/api/listing',
      operationId: 'updateListing',
      tag,
      summary: 'Change the listing of the person this agent speaks for',
      description:
        "Principal-reserved: listing is the person's choice, so the change waits for them to approve it in the owner window.",
      caller: reserved,
      body: ListingPatch,
      response: Listing,
      async handle({ caller, body }) {
        const { person } = await d.people.personOf(caller);
        return listingView((await d.people.updateListing(person, body, { agent: caller.address })).listing);
      },
    }),
  ];
}

export function recoveryRoutes(ctx: Ctx, d: Directory): ApiRoute[] {
  const Token = z.object({ token: z.string().max(100) });
  const failed = (e: unknown, status: number) =>
    htmlPage(page({ step: 'error', error: e instanceof WireError ? e.message : 'Something went wrong.' }), status);
  return [
    defineRoute({
      method: 'GET',
      path: '/api/recovery/:token',
      operationId: 'recoveryPage',
      tag: 'Directory',
      summary: 'The page behind the link sent to a person after their agent replaced its keys',
      caller: anyone,
      params: Token,
      produces: {
        status: 200,
        type: 'text/html',
        description: 'What happened, and a choice: confirm the agent or end it.',
      },
      async handle({ params, req, api }) {
        try {
          await spend(api, 'pages', ctx.config.rates.pages, clientKey(req.ip));
          const p = await d.pairings.byLink(params.token);
          return htmlPage(page({ step: 'ask', token: params.token, agent: p.address }));
        } catch (e) {
          return failed(e, 404);
        }
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/api/recovery/:token/:decision',
      operationId: 'decideRecovery',
      tag: 'Directory',
      summary: "The person's answer from that page: confirm the agent's new key, or end the agent",
      caller: anyone,
      params: Token.extend({ decision: z.enum(['confirm', 'end']) }),
      produces: { status: 200, type: 'text/html', description: 'Done.' },
      async handle({ params, req, api }) {
        try {
          await spend(api, 'pages', ctx.config.rates.pages, clientKey(req.ip));
          const p = await d.pairings.byLink(params.token);
          if (params.decision === 'confirm') await d.pairings.confirm(p);
          else await d.pairings.end(p, 'owner');
          return htmlPage(page({ step: params.decision, agent: p.address }));
        } catch (e) {
          return failed(e, 400);
        }
      },
    }),
  ];
}

function page(o: { step: 'ask' | 'confirm' | 'end' | 'error'; token?: string; agent?: string; error?: string }) {
  const name = `<strong>${esc(o.agent ?? '')}</strong>`;
  const bodies = {
    error: `<h1>Link expired</h1><p class="err" role="alert">${esc(o.error ?? '')}</p>`,
    confirm: `<h1>Confirmed</h1><p>${name} speaks for you as before.</p>`,
    end: `<h1>Ended</h1><p>${name} no longer speaks for anyone.</p>`,
    ask: `<h1>Your agent replaced its keys</h1>
<p>${name} proved control of its own address and bound a new key. Until you confirm, it may only converse for you.</p>
<form method="post" action="/api/recovery/${esc(o.token ?? '')}/confirm"><button type="submit">Yes, this is my agent</button></form>
<form method="post" action="/api/recovery/${esc(o.token ?? '')}/end"><button type="submit" class="secondary">No, end it</button></form>`,
  };
  return pageShell('SIMON agent keys', bodies[o.step]);
}
