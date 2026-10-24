/**
 * Malware scanning through ClamAV's daemon (clamd) over TCP, with its INSTREAM command. Run clamd beside
 * the server and point SIMON_CLAMD_HOST and SIMON_CLAMD_PORT at it.
 */
import net from 'node:net';

export type ScanVerdict = 'clean' | 'infected';

export interface Scanner {
  scan(data: Buffer): Promise<ScanVerdict>;
}

export class ClamdScanner implements Scanner {
  readonly host: string;
  readonly port: number;
  readonly timeoutMs: number;

  constructor(opts: { host: string; port: number; timeoutMs?: number }) {
    this.host = opts.host;
    this.port = opts.port;
    this.timeoutMs = opts.timeoutMs ?? 60_000;
  }

  scan(data: Buffer): Promise<ScanVerdict> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: this.host, port: this.port });
      let reply = '';
      const fail = (e: Error) => {
        socket.destroy();
        reject(e);
      };
      socket.setTimeout(this.timeoutMs, () => fail(new Error('clamd timed out')));
      socket.on('error', fail);
      socket.on('data', chunk => {
        reply += chunk.toString('utf8');
      });
      socket.on('end', () => {
        const r = reply.replace(/\0/g, '').trim();
        if (/\bOK$/.test(r)) resolve('clean');
        else if (/FOUND$/.test(r)) resolve('infected');
        else reject(new Error(`clamd: unexpected reply ${r.slice(0, 200)}`));
      });
      socket.on('connect', () => {
        socket.write('zINSTREAM\0');
        const CHUNK = 64 * 1024;
        for (let i = 0; i < data.length; i += CHUNK) {
          const piece = data.subarray(i, i + CHUNK);
          const len = Buffer.alloc(4);
          len.writeUInt32BE(piece.length);
          socket.write(len);
          socket.write(piece);
        }
        socket.end(Buffer.alloc(4));
      });
    });
  }
}
