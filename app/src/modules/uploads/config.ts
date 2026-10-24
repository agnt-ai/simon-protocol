/**
 * Upload checks. Bytes are scanned by clamd before the server keeps them; with no scanner, uploads are
 * refused, unless the operator chose otherwise (always so in development).
 *
 *   SIMON_CLAMD_HOST, SIMON_CLAMD_PORT        the scanner (port 3310 by default)
 *   SIMON_ALLOW_UNSCANNED_UPLOADS=1          keep uploads without scanning them
 *   SIMON_UPLOAD_BYTES_PER_DAY               bytes one agent may upload a day (default 500 MiB)
 */
import { int, text, type Env } from '../../lib/env.ts';

export interface UploadsConfig {
  clamd: { host: string; port: number } | null;
  unscanned: boolean;
  bytesPerDay: number;
}

export function readUploadsConfig(env: Env, dev: boolean): UploadsConfig {
  const host = text(env, 'SIMON_CLAMD_HOST');
  return {
    clamd: host ? { host, port: int(env, 'SIMON_CLAMD_PORT', 3310) } : null,
    unscanned: dev || env.SIMON_ALLOW_UNSCANNED_UPLOADS === '1',
    bytesPerDay: int(env, 'SIMON_UPLOAD_BYTES_PER_DAY', 500 * 1024 * 1024),
  };
}
