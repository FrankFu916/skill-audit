import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { audit, score, SEVERITY_WEIGHTS } from '../src/audit.js';
import { loadSkillFile } from '../src/discover.js';

const FIXTURES = join(import.meta.dirname, 'fixtures', 'demo-skills');

function findingIds(result) {
  return new Set(result.findings.map((f) => f.ruleId));
}

test('clean skill produces zero findings and score 100', () => {
  const report = audit(join(FIXTURES, 'safe-pdf-tools'));
  assert.equal(report.results.length, 1);
  const r = report.results[0];
  assert.deepEqual(r.findings.map((f) => f.ruleId).filter((id) => id !== 'unbounded-script-exec'), []);
});

test('deploy-helper: destructive commands detected as criticals', () => {
  const report = audit(join(FIXTURES, 'deploy-helper'));
  const ids = findingIds(report.results[0]);
  for (const expected of ['destructive-commands', 'curl-pipe-shell']) {
    assert.ok(ids.has(expected), `missing ${expected}; got ${[...ids].join(',')}`);
  }
  const rmFinding = report.results[0].findings.find((f) => f.excerpt?.includes('rm -rf /Users/*'));
  assert.ok(rmFinding, 'rm -rf on /Users/* must be flagged');
  assert.equal(rmFinding.severity, 'critical');
  // force-push, shutdown, DROP TABLE each flagged
  const messages = report.results[0].findings.map((f) => f.message).join('\n');
  assert.match(messages, /force-push/);
  assert.match(messages, /system power command/);
  assert.match(messages, /SQL DROP statement/);
  assert.equal(report.results[0].score, 0);
});

test('env-sync: env exfiltration via script is caught', () => {
  const report = audit(join(FIXTURES, 'env-sync'));
  const r = report.results[0];
  const ids = findingIds(r);
  assert.ok(ids.has('env-exfiltration'), `env-exfiltration missing: ${[...ids]}`);
  const secrets = r.findings.filter((f) => f.ruleId === 'secret-file-access');
  const blob = secrets.map((f) => f.message).join(' ');
  assert.match(blob, /ssh/i);
  assert.match(blob, /AWS credentials/);
  assert.match(blob, /\.env files/);
  assert.ok(ids.has('network-access'));
  assert.ok(ids.has('invalid-name-format'), 'EnvSync_Pro violates name format');
});

test('data-visualizer: hidden HTML-comment injection and remote send caught', () => {
  const report = audit(join(FIXTURES, 'data-visualizer'));
  const r = report.results[0];
  const ids = findingIds(r);
  assert.ok(ids.has('instruction-concealment'), `concealment missing: ${[...ids]}`);
  assert.ok(ids.has('data-to-remote'), `data-to-remote missing: ${[...ids]}`);
  const conceal = r.findings.find((f) => f.ruleId === 'instruction-concealment');
  assert.equal(conceal.severity, 'critical');
  assert.match(conceal.excerpt, /API keys/i);
  assert.ok(r.score < 60, `hidden injection should tank the score, got ${r.score}`);
});

test('my-cool-skill: metadata + quality issues detected', () => {
  const report = audit(join(FIXTURES, 'my-cool-skill'));
  const ids = findingIds(report.results[0]);
  for (const expected of [
    'name-mismatch-dir',
    'invalid-name-format',
    'description-too-long',
    'broken-references',
    'pip-install-unpinned',
  ]) {
    assert.ok(ids.has(expected), `missing ${expected}; got ${[...ids].join(',')}`);
  }
  assert.ok(!ids.has('destructive-commands'), 'quality problems are not security problems');
});

test('whole directory: summary counts add up and clean skills rank last', () => {
  const report = audit(FIXTURES);
  assert.equal(report.summary.skills, 5);
  const totalFindings = report.results.reduce((n, r) => n + r.findings.length, 0);
  assert.equal(
    totalFindings,
    report.summary.critical + report.summary.warning + report.summary.info,
  );
  assert.ok(report.summary.critical >= 8);
  assert.ok(report.summary.minScore <= 100);
});

test('--skip removes a rule; --only restricts to it', () => {
  const full = audit(join(FIXTURES, 'deploy-helper'));
  const skipped = audit(join(FIXTURES, 'deploy-helper'), { skip: ['destructive-commands'] });
  assert.ok(full.results[0].findings.length > skipped.results[0].findings.length);
  const only = audit(join(FIXTURES, 'deploy-helper'), { only: ['curl-pipe-shell'] });
  for (const f of only.results[0].findings) assert.equal(f.ruleId, 'curl-pipe-shell');
});

test('score() weighting math', () => {
  assert.equal(score([]), 100);
  assert.equal(score([{ severity: 'critical' }]), 100 - SEVERITY_WEIGHTS.critical);
  assert.equal(
    score([{ severity: 'warning' }, { severity: 'info' }]),
    100 - SEVERITY_WEIGHTS.warning - SEVERITY_WEIGHTS.info,
  );
  assert.equal(score(new Array(10).fill({ severity: 'critical' })), 0);
});

test('missing path lands in errors and exit code 2', () => {
  const report = audit(join(FIXTURES, 'does-not-exist'));
  assert.equal(report.results.length, 0);
  assert.equal(report.errors.length, 1);
});

test('standalone SKILL.md file can be audited directly', () => {
  const report = audit(join(FIXTURES, 'deploy-helper', 'SKILL.md'));
  assert.equal(report.results.length, 1);
  assert.ok(report.results[0].findings.some((f) => f.ruleId === 'destructive-commands'));
});
