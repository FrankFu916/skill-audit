/**
 * Discover and load agent skills from directories.
 *
 * A "skill" is a directory containing SKILL.md (Agent Skills spec). We also
 * tolerate single standalone SKILL.md files passed directly.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve, basename, dirname } from 'node:path';
import { splitFrontmatter, parseYaml } from './yaml.js';

export const SKILL_FILE = 'SKILL.md';

/**
 * @param {string} root file or directory to scan
 * @param {{ maxDepth?: number }} [options]
 * @returns {{ skills: object[], errors: object[] }}
 *   skills: parsed skill records
 *   errors: unreadable files/directories ({ path, message })
 */
export function discoverSkills(root, options = {}) {
  const maxDepth = options.maxDepth ?? 6;
  const skills = [];
  const errors = [];
  const target = resolve(root);

  let st;
  try {
    st = statSync(target);
  } catch (err) {
    return { skills, errors: [{ path: target, message: `cannot read: ${err.message}` }] };
  }

  if (st.isFile()) {
    skills.push(loadSkillFile(target, dirname(target)));
    return { skills, errors };
  }

  walk(target, target, 0, maxDepth, skills, errors);
  skills.sort((a, b) => a.path.localeCompare(b.path));
  return { skills, errors };
}

function walk(root, dir, depth, maxDepth, skills, errors) {
  if (depth > maxDepth) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    errors.push({ path: dir, message: `cannot list: ${err.message}` });
    return;
  }
  const hasSkillMd = entries.some(
    (e) => e.isFile() && e.name.toLowerCase() === SKILL_FILE.toLowerCase(),
  );
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      // Skip dependency / VCS noise; never recurse into a nested skill's deps.
      if (SKIP_DIRS.has(entry.name)) continue;
      if (hasSkillMd && entry.name !== '.claude') continue; // skill root: only top level matters
      walk(root, full, depth + 1, maxDepth, skills, errors);
      continue;
    }
    if (entry.isFile() && entry.name.toLowerCase() === SKILL_FILE.toLowerCase()) {
      skills.push(loadSkillFile(full, dirname(full)));
    }
  }
}

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  '.hg',
  '.svn',
  'dist',
  'build',
  'coverage',
  '.venv',
  '__pycache__',
]);

/** Load one SKILL.md into a normalized record. Never throws. */
export function loadSkillFile(file, skillDir) {
  const record = {
    name: basename(skillDir),
    path: file,
    dir: skillDir,
    source: relativeToCwd(file),
    frontmatter: {},
    body: '',
    bodyLines: [],
    raw: '',
    parseWarnings: [],
    files: [],
    error: null,
  };
    try {
      const raw = readFileSync(file, 'utf8');
      record.raw = raw;
      const { raw: fmText, body } = splitFrontmatter(raw);
      record.body = body;
      record.bodyLines = body.split('\n');
      // Absolute-file-line offset of bodyLines[0]: opening '---', the
      // frontmatter lines, and the closing '---' precede the body.
      record.bodyOffset =
        fmText === null ? 0 : 2 + fmText.split('\n').length;
      if (fmText === null) {
        record.parseWarnings.push('no YAML frontmatter block found (expected --- ... ---)');
      } else {
        const { data, warnings } = parseYaml(fmText);
        record.frontmatter = data;
        record.parseWarnings.push(...warnings.map((w) => `frontmatter: ${w}`));
      }
    record.files = listFiles(skillDir);
  } catch (err) {
    record.error = err.message;
  }
  return record;
}

function listFiles(skillDir) {
  const out = [];
  const visit = (dir, prefix, depth) => {
    if (depth > 4) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.name === '.' || entry.name === '..') continue;
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        visit(join(dir, entry.name), rel, depth + 1);
      } else if (entry.isFile()) {
        out.push(rel);
      }
    }
  };
  visit(skillDir, '', 0);
  return out;
}

export function relativeToCwd(p) {
  const cwd = process.cwd();
  const rel = p.startsWith(cwd) ? p.slice(cwd.length + 1) : p;
  return rel.startsWith('/') ? p : rel;
}
