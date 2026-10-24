/** The executable CLI preserves a migration gap and never accepts a resume token implicitly. */
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { it } from 'node:test';
import { generateKey } from '@agnt-protocol/protocol';
import { Agent } from '@agnt-protocol/client';
import { openAgent } from '@agnt-protocol/client/credentials';
import { readWaitState, saveWaitState, waitFile } from '@agnt-protocol/client/wait';
import { listen } from '../../js/test/fake-server.ts';

const CLI = path.resolve(import.meta.dirname, '../src/cli.ts');

/** Defined for a later authorized test run; no child exists until its test invokes this. */
function run(home: string, workspace: string, args: string[]): Promise<{ code: number; out: any; error: any }> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      process.execPath,
      [CLI, ...args],
      {
        timeout: 5000,
        env: { PATH: process.env.PATH, AGNT_HOME: home, AGNT_WORKSPACE: workspace, AGNT_TIMEOUT_MS: '1000' },
      },
      (error, stdout, stderr) => {
        try {
          resolve({
            code: error ? Number(error.code) : 0,
            out: stdout ? JSON.parse(stdout) : null,
            error: stderr ? JSON.parse(stderr).error : null,
          });
        } catch (parseError) {
          reject(parseError);
        }
      },
    );
    child.stdin!.end();
  });
}

it(
  'CLI JSON preserves migration details, requires --since, and leaves shared wait buffers untouched',
  { timeout: 15_000 },
  async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'agnt-cli-gap-'));
    const home = path.join(directory, 'home'),
      workspace = path.join(directory, 'work');
    fs.mkdirSync(workspace);
    const server = await listen();
    try {
      const created = await run(home, workspace, ['register', '--server', server.origin]);
      assert.equal(created.code, 0, JSON.stringify(created.error));
      const owner = openAgent(home, { fetch: server.fake.fetch });
      const resumeToken = (await owner.sync()).token;
      const author = new Agent({ server: server.origin, key: generateKey().privateKey, fetch: server.fake.fetch });
      await author.register();
      const sent = await author.send({ to: [owner.address!], text: 'retained after the reported gap' });
      const entry = (await owner.sync({ since: resumeToken })).messages[0];
      assert.equal(entry.id, sent.id);
      const details = { reason: 'history_migration', resumeToken };
      const calls: URL[] = [];
      const handle = server.fake.handle;
      server.fake.handle = async request => {
        const url = new URL(request.url);
        if (url.pathname === '/agnt/sync') {
          calls.push(url);
          if (!url.searchParams.has('since'))
            return new Response(
              JSON.stringify({
                type: 'about:blank',
                title: 'Token expired',
                code: 'token_expired',
                status: 410,
                retryable: false,
                detail: 'Sent history may be incomplete; explicitly resume after accepting the gap.',
                details,
              }),
              { status: 410, headers: { 'content-type': 'application/problem+json' } },
            );
        }
        return handle(request);
      };

      const refused = await run(home, workspace, ['sync']);
      assert.deepEqual(
        [refused.code, refused.out, refused.error.status, refused.error.code, refused.error.retryable],
        [1, null, 410, 'token_expired', false],
      );
      assert.deepEqual(refused.error.details, details);
      assert.equal(calls.length, 1, 'the executable did not send a hidden acceptance request');
      assert.equal(fs.existsSync(waitFile(home)), false, 'no shared checkpoint was silently saved');
      const resumed = await run(home, workspace, ['sync', '--since', resumeToken]);
      assert.equal(resumed.code, 0, JSON.stringify(resumed.error));
      assert.deepEqual(
        resumed.out.messages.map((e: { id: string }) => e.id),
        [sent.id],
      );
      assert.equal(calls.length, 2);
      assert.equal(calls[1].searchParams.get('since'), resumeToken);

      saveWaitState(home, { token: null, pending: [entry], seen: [] });
      const before = fs.readFileSync(waitFile(home));
      const waiting = await run(home, workspace, [
        'wait',
        '--from',
        'wanted@agents.test',
        '--timeout',
        '60',
        '--interval',
        '1',
      ]);
      assert.deepEqual([waiting.code, waiting.out, waiting.error.details], [1, null, details]);
      assert.equal(calls.length, 3, 'CLI wait also stops after the first nonretryable gap');
      assert.deepEqual(fs.readFileSync(waitFile(home)), before);
      assert.equal(fs.existsSync(path.join(home, 'wait.lock')), false);
      const buffered = await run(home, workspace, ['wait', '--timeout', '0', '--interval', '1']);
      assert.equal(buffered.code, 0, JSON.stringify(buffered.error));
      assert.equal(buffered.out.id, sent.id);
      assert.equal(calls.length, 3, 'buffered received data remains available without accepting resumeToken');
      assert.equal(readWaitState(home).token, null);
    } finally {
      await server.close();
      fs.rmSync(directory, { recursive: true, force: true });
    }
  },
);
