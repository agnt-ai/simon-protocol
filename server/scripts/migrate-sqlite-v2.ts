#!/usr/bin/env node
/** Explicit offline candidate conversion; never selects/promotes an operational database. */
import {
  createSqliteV2Candidate,
  SqliteMigrationRefusal,
  SqliteV2CleanupFailure,
  type SqliteV2Candidate,
} from '../src/store/sqlite-migration.ts';

const usage = `Usage: node server/scripts/migrate-sqlite-v2.ts --source FILE --directory NEW_BUNDLE --maintenance FILE

Builds a private, copy-first schema2 candidate with its same-directory app-arrivals.sqlite cohort.
Requires a private maintenance/drain attestation and externally held host fence, then acquires both
SQLite writer exclusions. Refuses incompatible authority, schema, data and projection states.
The original source/cohort remain recoverable. The candidate is NEVER selected or promoted.

Exit0: help only. Exit2: invalid arguments. Exit3: structurally verified copy with blocking activation
holds. Exit4: the same verified copy, but releasing the source handles failed afterwards; check the
source files and host before anything else. Exit1: refused/incomplete conversion. A successful copy
is NOT migration/activation readiness.
No --promote, recovery cancellation, queue drain, reset or force override is supported.
See server/sqlite-v2-migration.md before any separately authorized execution.
`;

async function main(args: string[]) {
  if (args.length === 1 && args[0] === '--help') {
    process.stdout.write(usage);
    return;
  }
  const allowed = new Set(['--source', '--directory', '--maintenance']);
  const values = new Map<string, string>();
  for (let i = 0; i < args.length; i += 2) {
    const name = args[i];
    const value = args[i + 1];
    if (!allowed.has(name) || values.has(name) || !value || value.startsWith('--')) {
      process.stderr.write('Invalid offline conversion arguments. Use --help.\n');
      process.exitCode = 2;
      return;
    }
    values.set(name, value);
  }
  if (values.size !== 3) {
    process.stderr.write('Required: --source, --directory and --maintenance. Use --help.\n');
    process.exitCode = 2;
    return;
  }
  try {
    const result = await createSqliteV2Candidate({
      source: values.get('--source')!,
      directory: values.get('--directory')!,
      maintenanceFile: values.get('--maintenance')!,
    });
    held(result);
    process.exitCode = 3;
  } catch (error) {
    if (error instanceof SqliteV2CleanupFailure) {
      // The bundle is VERIFIED and holds no REFUSED marker; only the release of the source handles failed.
      held(error.candidate, { cleanupFailed: true });
      process.exitCode = 4;
      return;
    }
    process.stderr.write(
      JSON.stringify({
        status: 'REFUSED',
        code: error instanceof SqliteMigrationRefusal ? error.code : 'conversion_failed',
        noOperationalPromotion: true,
      }) + '\n',
    );
    process.exitCode = 1;
  }
}

function held(result: SqliteV2Candidate, extra: Record<string, unknown> = {}) {
  process.stdout.write(
    JSON.stringify({
      status: result.status,
      activationBlocked: true,
      holds: result.holds,
      highWatermark: result.highWatermark,
      usableHeadroom: result.usableHeadroom,
      noOperationalPromotion: true,
      ...extra,
    }) + '\n',
  );
}

await main(process.argv.slice(2));
