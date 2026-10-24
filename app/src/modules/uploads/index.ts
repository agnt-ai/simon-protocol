/**
 * Upload checks, before the server keeps an agent's bytes (`PUT /agnt/parts/<sha256>`): a daily volume per
 * agent, then a malware scan. With no scanner, uploads are refused unless the operator chose otherwise.
 * Bytes fetched from other servers are their authors' servers' to scan.
 *
 * Hooks: upload.
 */
import type { Upload } from '@agnt-protocol/server';
import { ClamdScanner, type Scanner } from '../../adapters/scanner.ts';
import type { Ctx, Module } from '../../context.ts';
import { rateLimited, unavailable, unprocessable } from '../../lib/errors.ts';

const DAY_MS = 86_400_000;

export function uploadsModule(ctx: Ctx, scanner: Scanner | null = defaultScanner(ctx)): { module: Module } {
  /** Bytes each agent uploaded each UTC day, kept for that day only. */
  const volume = ctx.db.collection<{ _id: string; address: string; day: Date; bytes: number }>('uploads.volume');
  async function check({ address, sha256, bytes }: Upload) {
    const now = ctx.now().getTime();
    const day = now - (now % DAY_MS);
    const used = await volume.findOneAndUpdate(
      { _id: `${address} ${day}` },
      { $inc: { bytes: bytes.length }, $setOnInsert: { address, day: new Date(day) } },
      { upsert: true, returnDocument: 'after' },
    );
    if (used!.bytes > ctx.config.uploads.bytesPerDay) throw rateLimited(Math.ceil((day + DAY_MS - now) / 1000));
    if (!scanner) {
      if (ctx.config.uploads.unscanned) return;
      throw unavailable('This server scans uploads and has no scanner just now.', 3600);
    }
    if ((await scanner.scan(bytes)) === 'infected') {
      ctx.log('warn', 'infected upload refused', { address, sha256 });
      throw unprocessable('infected', 'The upload failed its malware scan.');
    }
  }
  return {
    module: {
      name: 'uploads',
      hooks: { upload: check },
      async init() {
        await volume.createIndex({ day: 1 });
        await volume.createIndex({ address: 1 });
      },
      async work() {
        const now = ctx.now().getTime();
        return (await volume.deleteMany({ day: { $lt: new Date(now - (now % DAY_MS)) } })).deletedCount;
      },
      forget: { agent: async address => void (await volume.deleteMany({ address })) },
    },
  };
}

function defaultScanner(ctx: Ctx): Scanner | null {
  const clamd = ctx.config.uploads.clamd;
  return clamd ? new ClamdScanner(clamd) : null;
}
