/**
 * Audit orchestration: run rules over discovered skills, aggregate results,
 * and compute a 0-100 health score.
 */

import { discoverSkills } from './discover.js';
import { RULES, severityRank } from './rules.js';

export const SEVERITY_WEIGHTS = { critical: 34, warning: 12, info: 3 };

/**
 * Audit a file or directory.
 * @param {string|string[]} roots
 * @param {{ only?: string[], skip?: string[] }} [options]
 */
export function audit(roots, options = {}) {
  const rootList = Array.isArray(roots) ? roots : [roots];
  const skills = [];
  const errors = [];
  for (const root of rootList) {
    const found = discoverSkills(root);
    skills.push(...found.skills);
    errors.push(...found.errors);
  }

  const activeRules = RULES.filter((r) => !options.skip?.includes(r.id)).filter(
    (r) => !options.only || options.only.includes(r.id),
  );

  const results = [];
  for (const skill of skills) {
    const findings = [];
    if (skill.error) {
      findings.push({
        ruleId: 'unreadable-file',
        severity: 'warning',
        title: 'File could not be read',
        type: 'metadata',
        message: skill.error,
        line: undefined,
        excerpt: undefined,
      });
    } else {
      for (const r of activeRules) {
        let ruleFindings;
        try {
          ruleFindings = r.run(skill) ?? [];
        } catch (err) {
          ruleFindings = [
            {
              message: `rule "${r.id}" crashed while running (${err.message}) — please report this`,
            },
          ];
        }
        for (const f of ruleFindings) {
          findings.push({
            ruleId: r.id,
            severity: r.severity,
            title: r.title,
            type: r.type,
            docs: r.docs,
            message: f.message,
            line: f.line,
            excerpt: f.excerpt,
          });
        }
      }
    }
    // de-duplicate identical (ruleId + line + message) findings
    const seen = new Set();
    const deduped = findings.filter((f) => {
      const key = `${f.ruleId}|${f.line ?? ''}|${f.message}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    deduped.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
    results.push({
      name: skill.name,
      source: skill.source,
      path: skill.path,
      error: skill.error,
      findings: deduped,
      score: score(deduped),
    });
  }

  results.sort((a, b) => a.score - b.score || a.name.localeCompare(b.name));

  return {
    results,
    errors,
    scannedAt: new Date().toISOString(),
    rulesRun: activeRules.length,
    summary: summarize(results),
  };
}

/** 0-100; 100 = nothing found. Caps at 0 regardless of how bad it gets. */
export function score(findings) {
  let penalty = 0;
  for (const f of findings) penalty += SEVERITY_WEIGHTS[f.severity] ?? 6;
  return Math.max(0, 100 - penalty);
}

function summarize(results) {
  const counts = { critical: 0, warning: 0, info: 0 };
  for (const r of results) {
    for (const f of r.findings) {
      counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    }
  }
  const scores = results.map((r) => r.score);
  return {
    skills: results.length,
    ...counts,
    minScore: scores.length ? Math.min(...scores) : null,
    avgScore: scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null,
  };
}

export function exitCode(report) {
  if (report.errors.length > 0) return 2;
  return report.summary.critical > 0 ? 1 : 0;
}
