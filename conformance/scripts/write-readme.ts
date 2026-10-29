/** Regenerate the check list in conformance/readme.md from the declarations in src/checks. */
import fs from 'node:fs';
import { catalogMarkdown } from '../src/suite.ts';

const path = new URL('../readme.md', import.meta.url);
const readme = fs.readFileSync(path, 'utf8');
const start = '<!-- checks:start -->';
const end = '<!-- checks:end -->';
const a = readme.indexOf(start);
const b = readme.indexOf(end);
if (a < 0 || b < a) throw new Error('readme.md lacks the check markers');
fs.writeFileSync(path, `${readme.slice(0, a + start.length)}\n\n${catalogMarkdown().trim()}\n\n${readme.slice(b)}`);
