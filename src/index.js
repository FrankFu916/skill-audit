/**
 * Public API surface. The CLI is thin sugar over these functions so that
 * other tools (VS Code extensions, GitHub Actions, web playgrounds) can
 * embed the auditor directly.
 */

export { discoverSkills, loadSkillFile, SKILL_FILE } from './discover.js';
export { parseYaml, splitFrontmatter } from './yaml.js';
export { RULES, ruleById, severityRank } from './rules.js';
export { audit, score, exitCode, SEVERITY_WEIGHTS } from './audit.js';
export { renderText, renderJson, renderSarif, renderMarkdown } from './render.js';

import { audit as runAudit } from './audit.js';
import { renderJson, renderSarif, renderMarkdown } from './render.js';

/** Convenience bundle used by bin/skill-audit.js and embedders. */
export function createAuditRunner({ version = '0.0.0' } = {}) {
  return {
    audit(roots, options) {
      const report = runAudit(roots, options);
      report.version = version;
      return report;
    },
    renderJson,
    renderSarif,
    renderMarkdown,
  };
}
