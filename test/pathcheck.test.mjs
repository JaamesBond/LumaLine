// test/pathcheck.test.mjs — the CLI PATH self-check.
//
// `lumaline install` deliberately writes ABSOLUTE paths into settings.json, so the status
// line never depends on PATH. Everything the user types afterwards does. These tests pin
// the detection + the shell-specific fix-it command across the install layouts npm
// actually produces (unix global, windows global, local project, npx cache), hermetically:
// the filesystem is a Set, the environment is a literal, so one OS proves the matrix.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  findExecutable, shimDirCandidates, resolveShimDir, isEphemeralRun,
  pathSetupCommand, pathStatus, pathAdviceLines,
} from '../src/lib/pathcheck.mjs';

const fakeFs = (...files) => {
  const set = new Set(files);
  return (p) => set.has(p);
};

// ── findExecutable ────────────────────────────────────────────────────────────────────

test('findExecutable finds the shim on a posix PATH', () => {
  const exists = fakeFs('/home/u/.npm-global/bin/lumaline');
  const found = findExecutable('lumaline', {
    env: { PATH: '/usr/bin:/home/u/.npm-global/bin' }, platform: 'linux', exists,
  });
  assert.equal(found, '/home/u/.npm-global/bin/lumaline');
});

test('findExecutable returns null when the shim dir is absent from PATH', () => {
  const exists = fakeFs('/home/u/.npm-global/bin/lumaline');
  const found = findExecutable('lumaline', { env: { PATH: '/usr/bin:/bin' }, platform: 'linux', exists });
  assert.equal(found, null);
});

test('findExecutable tolerates empty and quoted PATH entries', () => {
  const exists = fakeFs('/opt/x/lumaline');
  const found = findExecutable('lumaline', { env: { PATH: ':"/opt/x":' }, platform: 'linux', exists });
  assert.equal(found, '/opt/x/lumaline');
});

test('findExecutable uses PATHEXT on win32 (bare name never exists there)', () => {
  const exists = fakeFs('C:\\Users\\u\\AppData\\Roaming\\npm\\lumaline.cmd');
  const found = findExecutable('lumaline', {
    env: { Path: 'C:\\Windows;C:\\Users\\u\\AppData\\Roaming\\npm', PATHEXT: '.COM;.EXE;.BAT;.CMD' },
    platform: 'win32', exists,
  });
  assert.equal(found, 'C:\\Users\\u\\AppData\\Roaming\\npm\\lumaline.cmd');
});

test('findExecutable handles a missing PATH without throwing', () => {
  assert.equal(findExecutable('lumaline', { env: {}, platform: 'linux', exists: () => true }), null);
});

// ── shim location ─────────────────────────────────────────────────────────────────────

test('shimDirCandidates maps a unix global install to <prefix>/bin', () => {
  const dirs = shimDirCandidates('/home/u/.npm-global/lib/node_modules/lumaline/', { platform: 'linux' });
  assert.ok(dirs.includes('/home/u/.npm-global/bin'), dirs.join(','));
});

test('shimDirCandidates maps a windows global install to the prefix itself', () => {
  const dirs = shimDirCandidates('C:\\Users\\u\\AppData\\Roaming\\npm\\node_modules\\lumaline', { platform: 'win32' });
  assert.ok(dirs.includes('C:\\Users\\u\\AppData\\Roaming\\npm'), dirs.join(','));
});

test('shimDirCandidates covers a local project install via node_modules/.bin', () => {
  const dirs = shimDirCandidates('/proj/node_modules/lumaline', { platform: 'linux' });
  assert.ok(dirs.includes('/proj/node_modules/.bin'), dirs.join(','));
});

test('shimDirCandidates returns nothing for a git checkout (no node_modules segment)', () => {
  assert.deepEqual(shimDirCandidates('/home/u/projects/trustline', { platform: 'linux' }), []);
});

test('resolveShimDir picks the candidate that actually holds the shim', () => {
  const exists = fakeFs('/usr/bin/lumaline');
  assert.equal(
    resolveShimDir('/usr/lib/node_modules/lumaline', { platform: 'linux', exists }),
    '/usr/bin',
  );
});

test('resolveShimDir returns null when no candidate holds the shim', () => {
  assert.equal(
    resolveShimDir('/usr/lib/node_modules/lumaline', { platform: 'linux', exists: () => false }),
    null,
  );
});

test('isEphemeralRun detects the npx cache', () => {
  assert.equal(isEphemeralRun('/home/u/.npm/_npx/2f3a/node_modules/lumaline'), true);
  assert.equal(isEphemeralRun('/usr/lib/node_modules/lumaline'), false);
});

// ── shell-specific fix-it command ─────────────────────────────────────────────────────

test('pathSetupCommand emits fish_add_path for fish', () => {
  const r = pathSetupCommand('/home/u/.npm-global/bin', { env: { SHELL: '/usr/bin/fish' }, platform: 'linux' });
  assert.equal(r.shell, 'fish');
  assert.equal(r.command, 'fish_add_path "/home/u/.npm-global/bin"');
});

test('pathSetupCommand appends to the right rc file for zsh and bash', () => {
  const z = pathSetupCommand('/d', { env: { SHELL: '/bin/zsh' }, platform: 'linux' });
  assert.match(z.command, /~\/\.zshrc/);
  assert.match(z.command, /export PATH="\/d:\$PATH"/);
  const b = pathSetupCommand('/d', { env: { SHELL: '/bin/bash' }, platform: 'linux' });
  assert.match(b.command, /~\/\.bashrc/);
});

test('pathSetupCommand degrades to a plain export for an unknown shell', () => {
  const r = pathSetupCommand('/d', { env: { SHELL: '/usr/bin/ksh' }, platform: 'linux' });
  assert.equal(r.command, 'export PATH="/d:$PATH"');
  assert.match(r.note, /ksh/);
});

test('pathSetupCommand emits a persistent user-scoped PowerShell command on win32', () => {
  const r = pathSetupCommand('C:\\npm', { env: {}, platform: 'win32' });
  assert.equal(r.shell, 'powershell');
  assert.match(r.command, /SetEnvironmentVariable\('Path'.*'User'\)/);
  assert.match(r.command, /C:\\npm/);
});

// ── verdict + advice ──────────────────────────────────────────────────────────────────

const GLOBAL_ROOT = '/home/u/.npm-global/lib/node_modules/lumaline';

test('pathStatus is ok when the shim resolves from its own dir', () => {
  const s = pathStatus({
    pkgRoot: GLOBAL_ROOT, platform: 'linux',
    env: { PATH: '/usr/bin:/home/u/.npm-global/bin', SHELL: '/bin/bash' },
    exists: fakeFs('/home/u/.npm-global/bin/lumaline'),
  });
  assert.equal(s.ok, true);
  assert.equal(s.dir, '/home/u/.npm-global/bin');
  assert.deepEqual(pathAdviceLines(s), []);
});

test('pathStatus flags a missing PATH entry and carries the exact fix command', () => {
  const s = pathStatus({
    pkgRoot: GLOBAL_ROOT, platform: 'linux',
    env: { PATH: '/usr/bin:/bin', SHELL: '/usr/bin/fish' },
    exists: fakeFs('/home/u/.npm-global/bin/lumaline'),
  });
  assert.equal(s.ok, false);
  assert.equal(s.dir, '/home/u/.npm-global/bin');
  assert.equal(s.setup.command, 'fish_add_path "/home/u/.npm-global/bin"');
  const advice = pathAdviceLines(s).join('\n');
  assert.match(advice, /not on your PATH/);
  assert.match(advice, /fish_add_path "\/home\/u\/\.npm-global\/bin"/);
  // The user must not conclude the product is broken: the status line does not need PATH.
  assert.match(advice, /status line itself is unaffected/i);
});

test('pathStatus reports a shadowing install rather than a false all-clear', () => {
  const s = pathStatus({
    pkgRoot: GLOBAL_ROOT, platform: 'linux',
    env: { PATH: '/usr/local/bin:/home/u/.npm-global/bin', SHELL: '/bin/bash' },
    exists: fakeFs('/usr/local/bin/lumaline', '/home/u/.npm-global/bin/lumaline'),
  });
  assert.equal(s.ok, false);
  assert.equal(s.shadowed, true);
  assert.match(pathAdviceLines(s).join('\n'), /different `lumaline` is first on PATH/);
});

test('an npx run advises a real global install, not a PATH edit', () => {
  const s = pathStatus({
    pkgRoot: '/home/u/.npm/_npx/2f3a/node_modules/lumaline', platform: 'linux',
    env: { PATH: '/usr/bin', SHELL: '/bin/bash' }, exists: () => false,
  });
  assert.equal(s.ok, false);
  assert.equal(s.ephemeral, true);
  assert.equal(s.setup, null);
  const advice = pathAdviceLines(s).join('\n');
  assert.match(advice, /npm install -g lumaline/);
  assert.doesNotMatch(advice, /_npx/);
});

test('an unlocatable shim falls back to install advice instead of a bogus directory', () => {
  const s = pathStatus({
    pkgRoot: '/home/u/projects/trustline', platform: 'linux',
    env: { PATH: '/usr/bin', SHELL: '/bin/bash' }, exists: () => false,
  });
  assert.equal(s.ok, false);
  assert.equal(s.dir, null);
  assert.match(pathAdviceLines(s).join('\n'), /npm install -g lumaline/);
});
