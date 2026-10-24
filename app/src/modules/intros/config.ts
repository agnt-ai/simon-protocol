/**
 * Introductions.
 *
 *   SIMON_INTRO_TTL_DAYS         how long a request stays open (default 14)
 *   SIMON_INTRO_MAX_CARRIERS     how many carriers may be asked, in all (default 9)
 *   SIMON_INTRO_WAVE_HOURS       how long a wave of carriers has before the next is asked (default 24)
 *   SIMON_INTRO_ROUTE_DELAY_SEC  the least time before a request is routed, so the answer says nothing (default 30)
 */
import { int, type Env } from '../../lib/env.ts';

export interface IntrosConfig {
  ttlDays: number;
  maxCarriers: number;
  waveSize: number;
  waveHours: number;
  routeDelaySec: number;
}

export const readIntrosConfig = (env: Env): IntrosConfig => ({
  ttlDays: int(env, 'SIMON_INTRO_TTL_DAYS', 14),
  maxCarriers: int(env, 'SIMON_INTRO_MAX_CARRIERS', 9),
  waveSize: 3,
  waveHours: int(env, 'SIMON_INTRO_WAVE_HOURS', 24),
  routeDelaySec: int(env, 'SIMON_INTRO_ROUTE_DELAY_SEC', 30),
});
