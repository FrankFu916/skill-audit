import test from 'node:test';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';

const BIN = join(here, '..', 'bin', 'skill-audit.js');
const FIXTURES = join(here, 'fixtures', 'demo-skills');

function run(args, { expectCode } = {}) {
  try {
    const stdout = execFileSync(process.execPath, [BIN, ...args], {
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
    });
    return { stdout, code: 0 };
  } catch (err) {
    const code = err.status;
    if (expectCode !== undefined && code !== expectCode) {
      throw new Error(`expected exit ${expectCode}, got ${code}\nstdout: ${err.stdout}\nstderr: ${err.stderr}`);
    }
    return { stdout: err.stdout ?? '', stderr: err.stderr ?? '', code };
  }
}

test('cli --help and --version', () => {
  const help = run(['--help'], { expectCode: 0 });
  assert.match(help.stdout, /USAGE/);
  assert.match(help.stdout, /skill-audit <paths/);
  const ver = run(['--version'], { expectCode: 0 });
  assert.match(ver.stdout.trim(), /^\d+\.\d+\.\d+$/);
});

test('cli exits 1 on critical findings (clean dir exits 0)', () => {
  const bad = run([join(FIXTURES, 'deploy-helper'), '-f', 'compact']);
  assert.equal(bad.code, 1);
  assert.match(bad.stdout, /CRITICAL.*destructive-commands/);

  const good = run([join(FIXTURES, 'safe-pdf-tools'), '-f', 'compact']);
  assert.equal(good.code, 0);
  assert.match(good.stdout, /OK .*safe-pdf-tools/);
});

test('cli exits 2 for nonexistent path', () => {
  const r = run([join(FIXTURES, 'nope', 'nothing'), '-f', 'compact']);
  assert.equal(r.code, 2);
});

test('json output parses and has stable shape', () => {
  const r = run([FIXTURES, '-f', 'json']);
  assert.equal(r.code, 1); // criticals present
  const report = JSON.parse(r.stdout);
  assert.equal(report.summary.skills, 5);
  assert.ok(Array.isArray(report.results));
  for (const res of report.results) {
    for (const f of res.findings) {
      assert.ok(f.ruleId && f.severity && f.message);
      assert.ok(['critical', 'warning', 'info'].includes(f.severity));
    }
  }
});

test('sarif output validates against 2.1.0 expectations', () => {
  const r = run([FIXTURES, '-f', 'sarif']);
  const sarif = JSON.parse(r.stdout);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.$schema.includes('sarif-2.1.0'), true);
  const run0 = sarif.runs[0];
  assert.equal(run0.tool.driver.name, 'skill-audit');
  const declared = new Set(run0.tool.driver.rules.map((x) => x.id));
  assert.ok(declared.size >= 5);
  for (const result of run0.results) {
    assert.ok(['error', 'note'].includes(result.level));
    assert.ok(result.locations[0].physicalLocation.artifactLocation.uri.length > 0);
  }
  // rule ids referenced by results must be declared
  for (const result of run0.results) assert.ok(declared.has(result.ruleId));
});

test('markdown output contains table and severity counts', () => {
  const r = run([FIXTURES, '-f', 'markdown']);
  assert.match(r.stdout, /\| Skill \| Score \|/);
  assert.match(r.stdout, /# 🛡️ Skill Audit Report/);
  assert.match(r.stdout, /Totals:/);
});

test('--output writes a file and full format prints nothing to stdout', () => {
  const dir = mkdtempSync(join(tmpdir(), 'skill-audit-'));
  const out = join(dir, 'report.sarif');
  try {
    const r = run([join(FIXTURES, 'deploy-helper'), '-f', 'sarif', '-o', out]);
    assert.equal(r.stdout.trim(), ''); // file mode stays quiet on stdout
    const sarif = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(sarif.version, '2.1.0');
    assert.ok(r.code === 1 || r.code === 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('--skip suppresses the named rule only', () => {
  const withRule = run([join(FIXTURES, 'deploy-helper'), '-f', 'compact']).stdout;
  const without = run([
    join(FIXTURES, 'deploy-helper'),
    '-f',
    'compact',
    '--skip',
    'destructive-commands,curl-pipe-shell',
  ]).stdout;
  assert.match(withRule, /destructive-commands/);
  assert.doesNotMatch(without, /destructive-commands/);
  assert.doesNotMatch(without, /curl-pipe-shell/);
});

test('unknown option fails with usage error exit code 2', () => {
  const r = run(['--definitely-not-a-flag', FIXTURES]);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /unknown option/);
});

test('no args with no ~/.claude/skills shows help and exits 2', () => {
  const r = run([]);
  assert.equal(r.code, 2);
  assert.match(r.stdout, /USAGE/);
});
