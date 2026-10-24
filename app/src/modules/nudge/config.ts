/** The agent-only nudge: `SIMON_NUDGE_TURNS`, the run of messages with no person consulted that earns a notice (default 12). */
import { fail, int, type Env } from '../../lib/env.ts';

export interface NudgeConfig {
  turns: number;
}

export function readNudgeConfig(env: Env): NudgeConfig {
  const turns = int(env, 'SIMON_NUDGE_TURNS', 12);
  return turns >= 2 ? { turns } : fail('SIMON_NUDGE_TURNS is at least 2.');
}
