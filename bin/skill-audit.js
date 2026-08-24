#!/usr/bin/env node
/**
 * skill-audit — security & quality audit for AI agent skills.
 *
 * Usage:
 *   skill-audit <paths...> [options]
 *
 * Exit codes: 0 = clean (no criticals), 1 = critical findings, 2 = usage/IO error.
 */

import { createAuditRunner } from '../src/index.js';
import { renderText } from '../src/render.js';

const VERSION = '0.1.0';
const HELP = `skill-audit v${VERSION} — security & quality audit for AI agent skills

USAGE
  skill-audit <paths...> [options]

ARGUMENTS
  <paths...>              One or more skill directories, repos, or SKILL.md files.

OPTIONS
  -f, --format <type>     Output format: full | compact | json | sarif | markdown  (default: full)
  -o, --output <file>     Write report to a file instead of stdout.
      --only <rules>      Run only these rules (comma-separated ids).
      --skip <rules>      Skip these rules (comma-separated ids).
  -q, --quiet             Only print the summary block.
      --no-color          Disable colored output.
  -h, --help              Show this help.
  -v, --version           Show version number.

FORMATS
  full       Human-readable terminal report with per-finding details.
  compact    One line per finding, CI-log friendly.
  json       Machine-readable full report (stable schema within a major version).
  sarif      SARIF 2.1.0 for GitHub code scanning / CI dashboards.
  markdown   Drop into PR descriptions and wiki pages.

EXAMPLES
  skill-audit ~/.claude/skills                 # audit everything you've installed
  skill-audit ./skills/my-skill                # audit one skill before publishing
  skill-audit .claude/skills -f sarif -o out.sarif
  skill-audit ./skills --skip network-access,pip-install-unpinned

EXIT CODES
  0  no critical issues found
  1  critical issues found (useful for CI gates)
  2  bad arguments or unreadable paths

Docs: https://github.com/FrankFu916/skill-audit
`;

function parseArgs(argv) {
  const args = {
    paths: [],
    format: 'full',
    output: null,
    only: null,
    skip: null,
    quiet: false,
    color: process.env.NO_COLOR ? false : process.stdout.isTTY !== false,
    help: false,
    version: false,
  };
  const needsValue = new Set(['-f', '--format', '-o', '--output', '--only', '--skip']);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (needsValue.has(a)) {
      const value = argv[++i];
      if (value === undefined) fail(`missing value after ${a}`);
      switch (a) {
        case '-f':
        case '--format':
          args.format = value;
          break;
        case '-o':
        case '--output':
          args.output = value;
          break;
        case '--only':
          args.only = value;
          break;
        case '--skip':
          args.skip = value;
          break;
      }
      continue;
    }
    switch (a) {
      case '-q':
      case '--quiet':
        args.quiet = true;
        break;
      case '--no-color':
        args.color = false;
        break;
      case '-h':
      case '--help':
        args.help = true;
        return args;
      case '-v':
      case '--version':
        args.version = true;
        return args;
      default:
        if (a.startsWith('-')) fail(`unknown option: ${a}\n(run skill-audit --help)`);
        args.paths.push(a);
    }
  }
  return args;
}

function fail(msg) {
  console.error(`skill-audit: ${msg}`);
  process.exit(2);
}

const VALID_FORMATS = new Set(['full', 'compact', 'json', 'sarif', 'markdown']);

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(HELP);
    return 0;
  }
  if (args.version) {
    console.log(VERSION);
    return 0;
  }
  if (!VALID_FORMATS.has(args.format)) {
    fail(`unknown format "${args.format}" (choose: ${[...VALID_FORMATS].join(', ')})`);
  }
  if (args.paths.length === 0 && !args.help) {
    // Default to the conventional personal skills dir when it exists.
    const os = await import('node:os');
    const fs = await import('node:fs');
    const path = await import('node:path');
    const homeSkills = path.join(os.homedir(), '.claude', 'skills');
    if (fs.existsSync(homeSkills)) {
      args.paths.push(homeSkills);
    } else {
      console.log(HELP);
      return 2;
    }
  }

  const runner = createAuditRunner({ version: VERSION });
  const report = runner.audit(args.paths, {
    only: args.only ? splitList(args.only) : undefined,
    skip: args.skip ? splitList(args.skip) : undefined,
  });

  let text;
  switch (args.format) {
    case 'json':
      text = runner.renderJson(report);
      break;
    case 'sarif':
      text = runner.renderSarif(report);
      break;
    case 'markdown':
      text = runner.renderMarkdown(report);
      break;
    case 'compact':
      text = renderCompact(report);
      break;
    default:
      text = renderFullQuietlyAware(report, args);
  }

  if (args.output) {
    const { writeFileSync } = await import('node:fs');
    writeFileSync(args.output, `${text}\n`);
    if (args.format === 'full') {
      console.error(`report written to ${args.output} (${report.summary.skills} skills, ` +
        `${report.summary.critical} critical / ${report.summary.warning} warning / ${report.summary.info} info)`);
    }
  } else if (!(args.format === 'full' && text === '')) {
    console.log(text);
  }

  return report.errors.length > 0 ? 2 : report.summary.critical > 0 ? 1 : 0;
}

function renderFullQuietlyAware(report, args) {
  const full = renderText(report, { color: args.color });
  if (!args.quiet) return full;
  const s = report.summary;
  return [
    '',
    'Summary',
    `  ${s.skills} skill(s) audited · ${report.rulesRun} rules · ${s.critical} critical · ${s.warning} warnings · ${s.info} info`,
    '',
  ].join('\n');
}

function renderCompact(report) {
  const out = [];
  for (const r of report.results) {
    for (const f of r.findings) {
      const loc = f.line ? `:${f.line}` : '';
      out.push(`${f.severity.toUpperCase()} ${r.source}${loc} [${f.ruleId}] ${f.message}`);
    }
    if (r.findings.length === 0) {
      out.push(`OK ${r.source} [score ${r.score}/100]`);
    }
  }
  const s = report.summary;
  out.push(`-- ${s.skills} skill(s), ${s.critical} critical, ${s.warning} warnings, ${s.info} info --`);
  return out.join('\n');
}

function splitList(value) {
  return value.split(',').map((s) => s.trim()).filter(Boolean);
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(`skill-audit crashed: ${err?.stack || err}`);
    process.exit(2);
  });
