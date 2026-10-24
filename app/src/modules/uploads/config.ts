/**
 * Upload checks. Bytes are scanned by clamd before the server keeps them; with no scanner, uploads are
 * refused, unless the operator chose otherwise (always so in development).
 *
 *   AGNT_CLAMD_HOST, AGNT_CLAMD_PORT        the scanner (port 3310 by default)
 *   AGNT_ALLOW_UNSCANNED_UPLOADS=1          keep uploads without scanning them
 *   AGNT_UPLOAD_BYTES_PER_DAY               bytes one agent may upload a day (default 500 MiB)
 */
import { int, text, type Env } from '../../lib/env.ts';

export interface UploadsConfig {
  clamd: { host: string; port: number } | null;
  unscanned: boolean;
  bytesPerDay: number;
}

export function readUploadsConfig(env: Env, dev: boolean): UploadsConfig {
  const host = text(env, 'AGNT_CLAMD_HOST');
  return {
    clamd: host ? { host, port: int(env, 'AGNT_CLAMD_PORT', 3310) } : null,
    unscanned: dev || env.AGNT_ALLOW_UNSCANNED_UPLOADS === '1',
    bytesPerDay: int(env, 'AGNT_UPLOAD_BYTES_PER_DAY', 500 * 1024 * 1024),
  };
}
