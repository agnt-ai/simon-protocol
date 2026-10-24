/**
 * Reading settings from the environment, the same way everywhere: an empty value counts as unset (docker
 * compose passes unset variables as empty strings), and anything unreadable stops the process at startup.
 */
export type Env = Record<string, string | undefined>;

export class ConfigError extends Error {
  constructor(message: string) {
    super(`Configuration: ${message}`);
    this.name = 'ConfigError';
  }
}

export function fail(message: string): never {
  throw new ConfigError(message);
}

export const text = (env: Env, name: string): string | null => env[name] || null;

export function int(env: Env, name: string, fallback: number): number {
  const raw = env[name];
  if (!raw) return fallback;
  if (!/^\d{1,15}$/.test(raw)) fail(`${name} is a whole number, not "${raw}".`);
  return Number(raw);
}

export function oneOf<T extends string>(env: Env, name: string, allowed: readonly T[], fallback: T): T {
  const raw = env[name];
  if (!raw) return fallback;
  if (!allowed.includes(raw as T)) fail(`${name} is one of ${allowed.join(', ')}, not "${raw}".`);
  return raw as T;
}

export const list = (env: Env, name: string): string[] =>
  (env[name] ?? '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
