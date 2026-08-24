/**
 * Output renderers: pretty terminal text, JSON, SARIF 2.1.0, Markdown.
 * All renderers receive the same report object from audit().
 */

const ICONS = { critical: '✖', warning: '⚠', info: 'ℹ' };
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const GREEN = '\x1b[32m';
const RESET = '\x1b[0m';

export function renderText(report, options = {}) {
  const color = options.color ?? true;
  const c = (code, s) => (color ? `${code}${s}${RESET}` : String(s));
  const lines = [];

  const sevColor = { critical: RED, warning: YELLOW, info: CYAN };
  const scoreColor = (s) => (s >= 80 ? GREEN : s >= 50 ? YELLOW : RED);

  for (const r of report.results) {
    lines.push('');
    lines.push(c(BOLD, r.name) + c(DIM, `  — ${r.source}`));
    if (r.findings.length === 0) {
      lines.push(c(GREEN, '  ✓ no issues found'));
      continue;
    }
    for (const f of r.findings) {
      const loc = f.line ? `:${f.line}` : '';
      lines.push(`  ${c(sevColor[f.severity] ?? '', ICONS[f.severity] ?? '•')} ${c(sevColor[f.severity] ?? BOLD, f.severity.toUpperCase())} ${f.message}`);
      if (f.excerpt) lines.push(c(DIM, `      └─ ${truncate(f.excerpt)}`));
      lines.push(c(DIM, `      [${f.ruleId}]${loc ? ` at line ${f.line}` : ''}`));
    }
    const worst = r.findings[0]?.severity;
    lines.push('  ' + c(DIM, 'score: ') + c(scoreColor(r.score), `${r.score}/100`));
    void worst;
  }

  const s = report.summary;
  lines.push('');
  lines.push(c(BOLD, 'Summary'));
  lines.push(
    `  ${s.skills} skill(s) audited · ${report.rulesRun} rules · ` +
      c(RED, `${s.critical} critical`) + ' · ' +
      c(YELLOW, `${s.warning} warnings`) + ' · ' +
      c(CYAN, `${s.info} info`),
  );
  if (report.errors.length > 0) {
    for (const e of report.errors) lines.push(c(YELLOW, `  ! skipped: ${e.path} (${e.message})`));
  }
  lines.push('');
  return lines.join('\n');
}

function truncate(s, n = 140) {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

/* ------------------------------------------------------------------ */

export function renderJson(report) {
  return JSON.stringify(report, null, 2);
}

/* ------------------------------------------------------------------ */

/** SARIF 2.1.0 — uploadable to GitHub code scanning. */
export function renderSarif(report) {
  const rulesById = new Map();
  const resultsArr = [];
  for (const r of report.results) {
    for (const f of r.findings) {
      if (!rulesById.has(f.ruleId)) {
        rulesById.set(f.ruleId, {
          id: f.ruleId,
          name: f.title,
          shortDescription: { text: f.title },
          help: { text: f.docs ?? f.title },
          defaultConfiguration: { level: sarifLevel(f.severity) },
          properties: { type: f.type, securitySeverity: sarifRank(f.severity) },
        });
      }
      resultsArr.push({
        ruleId: f.ruleId,
        level: sarifLevel(f.severity),
        message: { text: f.message },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: relativeUri(r.path) },
              ...(f.line
                ? { region: { startLine: f.line } }
                : {}),
            },
          },
        ],
        partialFingerprints: { skillAuditFinding: `${f.ruleId}:${relativeUri(r.path)}:${f.line ?? ''}:${hashMessage(f.message)}` },
      });
    }
  }
  return JSON.stringify(
    {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'skill-audit',
              informationUri: 'https://github.com/FrankFu916/skill-audit',
              version: report.version ?? '0.0.0',
              rules: [...rulesById.values()],
            },
          },
          results: resultsArr,
        },
      ],
    },
    null,
    2,
  );
}

function sarifLevel(sev) {
  return sev === 'info' ? 'note' : 'error';
}

function sarifRank(sev) {
  return sev === 'critical' ? '9.5' : sev === 'warning' ? '6.0' : '2.0';
}

function relativeUri(p) {
  // SARIF wants repo-relative URIs with forward slashes.
  return p.replace(/\\/g, '/').replace(/^\//, '');
}

function hashMessage(msg) {
  let h = 0;
  for (let i = 0; i < msg.length; i++) {
    h = (h * 31 + msg.charCodeAt(i)) | 0;
  }
  return Math.abs(h).toString(36);
}

/* ------------------------------------------------------------------ */

export function renderMarkdown(report) {
  const L = [];
  L.push('# 🛡️ Skill Audit Report');
  L.push('');
  L.push(`> Audited **${report.summary.skills}** skill(s) with **${report.rulesRun}** rules on ${report.scannedAt}.`);
  L.push('');
  L.push('| Skill | Score | Critical | Warning | Info |');
  L.push('|---|---|---|---|---|');
  for (const r of report.results) {
    const counts = countBy(r.findings);
    L.push(`| \`${r.name}\` | ${r.score}/100 | ${counts.critical || 0} | ${counts.warning || 0} | ${counts.info || 0} |`);
  }
  for (const r of report.results) {
    if (r.findings.length === 0) continue;
    L.push('');
    L.push(`## ${r.name} — ${r.score}/100`);
    L.push('');
    for (const f of r.findings) {
      const loc = f.line ? `, line ${f.line}` : '';
      L.push(`- **${f.severity.toUpperCase()}** ${f.message} *(rule: \`${f.ruleId}\`${loc})*`);
      if (f.excerpt) L.push(`  > \`${escapeMd(f.excerpt.slice(0, 200))}\``);
    }
  }
  const s = report.summary;
  L.push('');
  L.push(`**Totals:** ${s.critical} critical · ${s.warning} warnings · ${s.info} info`);
  return L.join('\n');

  function countBy(findings) {
    const out = {};
    for (const f of findings) out[f.severity] = (out[f.severity] ?? 0) + 1;
    return out;
  }

  function escapeMd(str) {
    return str.replace(/[`|]/g, (ch) => `\\${ch}`).replace(/\n/g, ' ');
  }
}
