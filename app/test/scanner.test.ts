import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { ClamdScanner } from '../src/adapters/scanner.ts';

/** A fake clamd that speaks INSTREAM: length-prefixed chunks ending with a zero length. */
function fakeClamd(
  verdict: (data: Buffer) => string,
): Promise<{ port: number; close: () => void; received: Buffer[] }> {
  const received: Buffer[] = [];
  return new Promise(resolve => {
    const server = net.createServer(sock => {
      let buf = Buffer.alloc(0);
      sock.on('data', d => {
        buf = Buffer.concat([buf, d]);
        const cmd = 'zINSTREAM\0';
        if (!buf.subarray(0, cmd.length).equals(Buffer.from(cmd))) return;
        let off = cmd.length;
        const chunks: Buffer[] = [];
        for (;;) {
          if (buf.length < off + 4) return;
          const len = buf.readUInt32BE(off);
          if (len === 0) break;
          if (buf.length < off + 4 + len) return;
          chunks.push(buf.subarray(off + 4, off + 4 + len));
          off += 4 + len;
        }
        const data = Buffer.concat(chunks);
        received.push(data);
        sock.end(`stream: ${verdict(data)}\0`);
      });
    });
    server.listen(0, '127.0.0.1', () =>
      resolve({ port: (server.address() as net.AddressInfo).port, close: () => server.close(), received }),
    );
  });
}

describe('ClamdScanner', () => {
  it('streams the bytes in chunks and reads clean and infected verdicts', async () => {
    const d = await fakeClamd(data => (data.includes('EICAR') ? 'Eicar-Signature FOUND' : 'OK'));
    try {
      const scanner = new ClamdScanner({ host: '127.0.0.1', port: d.port });
      const big = Buffer.alloc(200_000, 7);
      assert.equal(await scanner.scan(big), 'clean');
      assert.deepEqual(d.received[0], big);
      assert.equal(await scanner.scan(Buffer.from('xx EICAR xx')), 'infected');
    } finally {
      d.close();
    }
  });

  it('fails on an unexpected reply rather than calling it clean', async () => {
    const d = await fakeClamd(() => 'INSTREAM size limit exceeded. ERROR');
    try {
      await assert.rejects(new ClamdScanner({ host: '127.0.0.1', port: d.port }).scan(Buffer.from('data')));
    } finally {
      d.close();
    }
  });
});
