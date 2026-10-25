/**
 * Write app/openapi.json: the API document of an application running every module, built from the route
 * definitions without a database (MongoDB's handles connect only when used), formatted as Prettier would.
 * A test fails when the committed copy is stale.
 *
 *   npm run openapi -w app
 */
import fs from 'node:fs';
import path from 'node:path';
import { generateKey } from '@agnt-sdk/simon-protocol';
import { defineConfig } from '@agnt-sdk/simon-server';
import { MongoClient } from 'mongodb';
import * as prettier from 'prettier';
import { createApp } from '../src/app.ts';
import { loadAppConfig } from '../src/config.ts';
import { openApiDocument } from '../src/http/openapi.ts';

export const DOCUMENT = path.resolve(import.meta.dirname, '../openapi.json');

export async function documentFile(): Promise<string> {
  const origin = 'https://simon.example.com';
  const server = defineConfig({
    origin,
    dev: true,
    hostedDomains: ['example.com'],
    serverKey: generateKey().privateKey,
  });
  const db = new MongoClient('mongodb://127.0.0.1:1').db('unused');
  const app = createApp({ config: loadAppConfig({}, server), db, mail: null, sms: null, worker: false });
  return prettier.format(JSON.stringify(openApiDocument(app.routes, origin)), { parser: 'json', printWidth: 120 });
}

if (import.meta.main) {
  fs.writeFileSync(DOCUMENT, await documentFile());
  console.log(`wrote ${path.relative(process.cwd(), DOCUMENT)}`);
}
