/**
 * Principal-reserved calls (owner/requests.ts): the person lists what their agents asked and decides each,
 * and an agent reads how its own request ended.
 */
import { z } from 'zod';
import { agent, defineRoute, Paged, PageQuery, type ApiRoute, type Caller } from '../../../http/route.ts';
import { idPattern } from '../../../lib/ids.ts';
import { pageOf } from '../../../store/db.ts';
import type { Session } from '../oauth.ts';
import { RequestView, type Requests } from '../requests.ts';

const Id = z.object({ requestId: z.string().regex(idPattern('request')) });

export function requestRoutes(requests: Requests, owner: Caller<Session>): ApiRoute[] {
  return [
    defineRoute({
      method: 'GET',
      path: '/api/me/requests',
      operationId: 'listMyRequests',
      tag: 'Owner',
      summary: 'What my agents asked to do that is mine to decide, newest first',
      caller: owner,
      query: PageQuery,
      response: Paged(RequestView),
      handle: async ({ caller, query }) =>
        pageOf(await requests.list(caller.identifiers, query), query, r => requests.view(r)),
    }),
    defineRoute({
      method: 'POST',
      path: '/api/me/requests/:requestId',
      operationId: 'decideMyRequest',
      tag: 'Owner',
      summary: 'Approve a request, which runs the call as my agent made it, or decline it',
      description:
        "The answer is the request as it ended: approved with the call's answer, failed with its error, or declined.",
      caller: owner,
      params: Id,
      body: z.strictObject({ decision: z.enum(['approve', 'decline']) }),
      response: RequestView,
      handle: async ({ caller, params, body, req, api }) =>
        requests.view(await requests.decide(params.requestId, caller.identifiers, body.decision, req, api)),
    }),
    defineRoute({
      method: 'GET',
      path: '/api/agents/me/requests/:requestId',
      operationId: 'getRequest',
      tag: 'Agents',
      summary: 'A call this agent made that waits on its person, or how it ended',
      caller: agent,
      params: Id,
      response: RequestView,
      handle: async ({ caller, params }) => requests.view(await requests.ofAgent(caller.address, params.requestId)),
    }),
  ];
}
