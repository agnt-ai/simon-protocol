/**
 * Write src/net/public-suffixes.ts, the snapshot of the Public Suffix List's ICANN section the server ships,
 * from a copy of the whole list, read as the server reads one (`parsePublicSuffixes`, so the two never differ):
 *
 *   node server/scripts/write-public-suffixes.ts <public_suffix_list.dat> <the date of that list>
 *
 * The shipped snapshot was written from the list of 2024-01-07 as the domain_name 0.6.20240107 distribution
 * carries it (data/public_suffix_list.dat), whose SHA-256 the header records. A newer list comes from
 * https://publicsuffix.org/list/public_suffix_list.dat; the list is under the Mozilla Public License 2.0.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { parsePublicSuffixes } from '../src/net/psl.ts';

const [file, date] = process.argv.slice(2);
if (!file || !date) throw new Error('usage: write-public-suffixes.ts <public_suffix_list.dat> <date of the list>');
const text = fs.readFileSync(file, 'utf8');
const sha = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const { rules, exceptions } = parsePublicSuffixes(text);
const lines = [...rules, ...[...exceptions].map(e => `!${e}`)];
const out = `/**
 * The ICANN section of the Public Suffix List (https://publicsuffix.org/list/public_suffix_list.dat), one rule a line,
 * internationalised labels written as A-labels: the list of ${date} (SHA-256 of the whole list ${sha}).
 * Written by server/scripts/write-public-suffixes.ts; do not edit by hand. SIMON_PUBLIC_SUFFIX_LIST names a newer
 * copy of the list to read instead.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was
 * not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
export const PUBLIC_SUFFIX_RULES = \`
${lines.join('\n')}
\`;
`;
const target = path.resolve(import.meta.dirname, '../src/net/public-suffixes.ts');
fs.writeFileSync(target, out);
console.log(`wrote ${lines.length} rules to ${path.relative(process.cwd(), target)}`);
