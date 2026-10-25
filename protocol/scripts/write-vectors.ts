/**
 * Write spec/vectors/v2.json from the reference code, and keep the ML-DSA signatures it used. The vectors
 * test fails until this is rerun after a change.
 */
import fs from 'node:fs';
import path from 'node:path';
import { saveFixedSignatures } from '../test/fixtures.ts';
import { buildVectors } from '../test/vectors.ts';

const file = path.resolve(import.meta.dirname, '../../spec/vectors/v2.json');
fs.writeFileSync(file, `${JSON.stringify(await buildVectors(), null, 2)}\n`);
saveFixedSignatures();
console.log(`wrote ${path.relative(process.cwd(), file)}`);
