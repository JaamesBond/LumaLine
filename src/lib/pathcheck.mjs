// PATH self-check for the `lumaline` CLI shim.
//
// The status line itself NEVER depends on PATH — `lumaline install` writes an absolute
// node path + absolute script path into settings.json on purpose (src/install.mjs). But
// every *other* command the user is told to run (`uninstall`, `login`, `earnings`,
// `connect`, `doctor`) is typed by hand, so it needs the npm shim to be resolvable. A
// global install into a prefix that isn't on PATH (nvm/asdf switch, ~/.npm-global,
// Homebrew, a fresh Windows profile) silently produces "command not found" — and the
// user's first conclusion is that lumaline is broken.
//
// Pure + injectable (env/platform/exists) so the whole matrix is hermetically testable
// on one OS. Zero runtime deps, node: built-ins only.
import path from 'node:path';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const pathFor = (platform) => (platform === 'win32' ? path.win32 : path.posix);
const PACKAGE_ROOT = fileURLToPath(new URL('../../', import.meta.url));

// Executable name variants to probe. On Windows npm installs a `.cmd`/`.ps1` shim, so a
// bare name never exists on disk; PATHEXT drives the extension list there.
function nameVariants(name, platform, env) {
  if (platform !== 'win32') return [name];
  const exts = (env.PATHEXT || '.COM;.EXE;.BAT;.CMD').split(';').map((e) => e.trim()).filter(Boolean);
  // PATHEXT is conventionally UPPERCASE while npm writes `lumaline.cmd`. NTFS is
  // case-insensitive so either probe hits there, but a case-sensitive mount (or a
  // case-sensitive `exists` in tests) needs both spellings.
  const out = [name];
  for (const e of exts) { out.push(name + e, name + e.toLowerCase()); }
  return [...new Set(out)];
}

/** First match for `name` across PATH, or null. Returns the full path so callers can
 *  detect a *different* lumaline shadowing ours. */
export function findExecutable(name, opts = {}) {
  const { env = process.env, platform = process.platform, exists = existsSync } = opts;
  const pp = pathFor(platform);
  const raw = env.PATH ?? env.Path ?? env.path ?? '';
  const delim = platform === 'win32' ? ';' : ':';
  for (const entryRaw of String(raw).split(delim)) {
    // Windows PATH entries are commonly quoted; a trailing separator yields an empty entry.
    const entry = entryRaw.trim().replace(/^"|"$/g, '');
    if (!entry) continue;
    for (const candidate of nameVariants(name, platform, env)) {
      const full = pp.join(entry, candidate);
      if (exists(full)) return full;
    }
  }
  return null;
}

/** Directories where npm would have put our shim, given the installed package root.
 *  Order matters only as a tie-break — callers confirm by probing for the shim itself. */
export function shimDirCandidates(pkgRoot, opts = {}) {
  const { platform = process.platform } = opts;
  const pp = pathFor(platform);
  const parts = String(pkgRoot).split(/[\\/]+/);
  const i = parts.lastIndexOf('node_modules');
  if (i < 0) return [];                                  // running from a git checkout
  const nmDir = parts.slice(0, i + 1).join(pp.sep);       // …/node_modules
  const nmParent = parts.slice(0, i).join(pp.sep) || pp.sep;
  return platform === 'win32'
    // Global: <prefix>\node_modules\lumaline → shims land in <prefix> itself.
    ? [pp.join(nmDir, '.bin'), nmParent]
    // Global: <prefix>/lib/node_modules/lumaline → shims land in <prefix>/bin.
    : [pp.join(nmDir, '.bin'), pp.join(nmParent, '..', 'bin')];
}

/** The directory that actually holds our shim, or null if none does. */
export function resolveShimDir(pkgRoot, opts = {}) {
  const { platform = process.platform, exists = existsSync, bin = 'lumaline', env = process.env } = opts;
  const pp = pathFor(platform);
  for (const dir of shimDirCandidates(pkgRoot, { platform })) {
    for (const candidate of nameVariants(bin, platform, env)) {
      if (exists(pp.join(dir, candidate))) return dir;
    }
  }
  return null;
}

/** `npx lumaline …` runs out of npm's ephemeral cache — adding that to PATH is wrong advice. */
export function isEphemeralRun(pkgRoot) {
  return /(^|[\\/])_npx[\\/]/.test(String(pkgRoot));
}

/** The exact one-liner that puts `dir` on PATH for the user's shell, persistently. */
export function pathSetupCommand(dir, opts = {}) {
  const { env = process.env, platform = process.platform } = opts;
  if (platform === 'win32') {
    return {
      shell: 'powershell',
      command: `[Environment]::SetEnvironmentVariable('Path', "$env:Path;${dir}", 'User')`,
      note: 'then open a new terminal',
    };
  }
  const shell = String(env.SHELL || '').split('/').pop() || 'sh';
  if (shell === 'fish') {
    return { shell, command: `fish_add_path "${dir}"`, note: 'persists across sessions' };
  }
  const rc = shell === 'zsh' ? '~/.zshrc' : shell === 'bash' ? '~/.bashrc' : null;
  if (!rc) {
    return {
      shell,
      command: `export PATH="${dir}:$PATH"`,
      note: `add that line to your ${shell} startup file to make it persist`,
    };
  }
  return {
    shell,
    command: `echo 'export PATH="${dir}:$PATH"' >> ${rc} && source ${rc}`,
    note: null,
  };
}

/**
 * Full PATH verdict for the running install.
 * ok      — `lumaline` resolves on PATH right now
 * dir     — where our shim lives (null if we can't find it)
 * shadowed— resolvable, but the first hit is a DIFFERENT install than ours
 */
export function pathStatus(opts = {}) {
  const {
    pkgRoot = PACKAGE_ROOT, env = process.env, platform = process.platform,
    exists = existsSync, bin = 'lumaline',
  } = opts;
  const pp = pathFor(platform);
  const found = findExecutable(bin, { env, platform, exists });
  const dir = resolveShimDir(pkgRoot, { platform, exists, bin, env });
  const ephemeral = isEphemeralRun(pkgRoot);
  const shadowed = !!(found && dir && pp.dirname(found) !== dir);
  return {
    ok: !!found && !shadowed,
    found,
    dir,
    ephemeral,
    shadowed,
    setup: dir && !ephemeral ? pathSetupCommand(dir, { env, platform }) : null,
  };
}

/**
 * Human-readable advice lines (empty array when everything is fine). Returned as strings
 * rather than printed so install/doctor share one tested implementation.
 */
export function pathAdviceLines(status) {
  const out = [];
  if (status.ephemeral) {
    if (status.ok) return out;
    out.push('Note: this ran from a temporary npx cache, so no `lumaline` command was installed.');
    out.push('  Install it for real:  npm install -g lumaline');
    return out;
  }
  if (status.shadowed) {
    out.push(`⚠ A different \`lumaline\` is first on PATH: ${status.found}`);
    out.push(`  This install lives in: ${status.dir}`);
    out.push('  Typed commands will hit the other one until you fix the PATH order.');
    return out;
  }
  if (status.ok) return out;
  out.push('⚠ `lumaline` is not on your PATH — typed commands (uninstall/login/earnings) will fail.');
  out.push('  (The status line itself is unaffected: install wrote absolute paths into settings.json.)');
  if (!status.dir) {
    out.push('  Could not locate the installed shim. If you installed globally, run:  npm install -g lumaline');
    return out;
  }
  out.push(`  Add it with:\n\n    ${status.setup.command}\n`);
  if (status.setup.note) out.push(`  (${status.setup.note})`);
  return out;
}
