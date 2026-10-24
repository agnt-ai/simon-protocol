/**
 * The one directory the CLI and the MCP server read and write files in, for a model that runs them on
 * the word of whatever it last read. A path names a file in the workspace, after every symbolic link is
 * resolved, and never one under AGNT_HOME, where the keys live, even when AGNT_HOME is inside the
 * workspace.
 *
 *   AGNT_WORKSPACE      the workspace; default the current working directory
 */
import fs from 'node:fs';
import path from 'node:path';
import { AgntError } from './errors.ts';

export interface Workspace {
  /** The workspace, its links resolved. */
  root: string;
  /** AGNT_HOME, its links resolved as far as it exists. */
  home: string;
}

/** The workspace for an environment and a key directory. */
export function workspace(home: string, env: NodeJS.ProcessEnv = process.env, cwd = process.cwd()): Workspace {
  const root = path.resolve(cwd, env.AGNT_WORKSPACE || '.');
  let real: string;
  try {
    real = fs.realpathSync(root);
  } catch {
    throw refused('AGNT_WORKSPACE', `The workspace ${root} does not exist.`);
  }
  return { root: real, home: realAsFarAsExists(path.resolve(cwd, home)) };
}

/** A file to read: it exists, and it and every link to it lie in the workspace and outside AGNT_HOME. */
export function readablePath(ws: Workspace, file: string, field = 'path'): string {
  const wanted = path.resolve(ws.root, file);
  let real: string;
  try {
    real = fs.realpathSync(wanted);
  } catch {
    throw refused(field, `No file ${file} in the workspace.`);
  }
  confine(ws, real, file, field);
  if (isHomeFile(ws, real)) throw refused(field, `${file} is a hard link to a file in the agent's key directory.`);
  return real;
}

/** Whether a file is one of AGNT_HOME's own under another name, through a hard link. */
function isHomeFile(ws: Workspace, file: string): boolean {
  const st = fs.statSync(file);
  if (st.nlink < 2) return false;
  let names: string[];
  try {
    names = fs.readdirSync(ws.home);
  } catch {
    return false;
  }
  return names.some(n => {
    const h = fs.statSync(path.join(ws.home, n), { throwIfNoEntry: false });
    return h !== undefined && h.ino === st.ino && h.dev === st.dev;
  });
}

/** Read a file in the workspace. */
export function readFile(ws: Workspace, file: string, field = 'path'): Buffer {
  return fs.readFileSync(readablePath(ws, file, field));
}

/**
 * Where a file would be written in the workspace: its directory must exist there, and a link in the
 * file's own place is refused, not followed, so nothing outside can be overwritten through one. Check
 * before fetching what to write, so a refusal costs nothing.
 */
export function writablePath(ws: Workspace, file: string, field = 'path'): string {
  const wanted = path.resolve(ws.root, file);
  let dir: string;
  try {
    dir = fs.realpathSync(path.dirname(wanted));
  } catch {
    throw refused(field, `No directory for ${file} in the workspace.`);
  }
  const target = path.join(dir, path.basename(wanted));
  confine(ws, target, file, field);
  if (fs.lstatSync(target, { throwIfNoEntry: false })?.isSymbolicLink()) throw linkRefused(file, field);
  return target;
}

/** Write a file in the workspace (see `writablePath`); answers its path relative to the workspace. */
export function writeFile(ws: Workspace, file: string, bytes: Uint8Array, field = 'path'): string {
  const target = writablePath(ws, file, field);
  const { O_WRONLY, O_CREAT, O_TRUNC, O_NOFOLLOW } = fs.constants;
  let fd: number;
  try {
    // O_NOFOLLOW: a link put in place since the check is refused too.
    fd = fs.openSync(target, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0o644);
  } catch (e) {
    if (['ELOOP', 'EMLINK'].includes((e as NodeJS.ErrnoException).code ?? '')) throw linkRefused(file, field);
    throw e;
  }
  try {
    fs.writeSync(fd, bytes);
  } finally {
    fs.closeSync(fd);
  }
  return path.relative(ws.root, target);
}

const linkRefused = (file: string, field: string) =>
  refused(field, `${file} is a symbolic link; files are written only as plain files.`);

function confine(ws: Workspace, real: string, asked: string, field: string) {
  if (!within(ws.root, real)) {
    throw refused(field, `${asked} is outside the workspace. Files are read and written only in the workspace.`);
  }
  if (within(ws.home, real)) throw refused(field, `${asked} is in the agent's key directory, which no tool touches.`);
}

const within = (dir: string, p: string) => {
  const r = path.relative(dir, p);
  return r === '' || (r !== '..' && !r.startsWith(`..${path.sep}`) && !path.isAbsolute(r));
};

/** A path with the links resolved in the part of it that exists. */
function realAsFarAsExists(p: string): string {
  const rest: string[] = [];
  for (let at = p; ; at = path.dirname(at)) {
    try {
      return path.join(fs.realpathSync(at), ...rest.reverse());
    } catch {
      if (path.dirname(at) === at) return p;
      rest.push(path.basename(at));
    }
  }
}

const refused = (field: string, message: string) => new AgntError('path_refused', message, { details: { field } });
