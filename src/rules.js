/**
 * Audit rules for SKILL.md files.
 *
 * Every rule is a plain object: { id, title, severity, type, docs, run }.
 * `run(skill)` returns an array of findings: { message, line?, excerpt? }.
 *
 * Severity model:
 *   critical — credential theft, destructive commands, stealth/exfiltration
 *   warning  — prompt-injection surface, risky patterns, obfuscation
 *   info     — quality/spec-compliance issues that weaken the skill
 */

const SEVERITY_ORDER = { critical: 0, warning: 1, info: 2 };

export const RULES = [];

function rule(def) {
  RULES.push({ severity: 'info', ...def });
  return def;
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

function frontmatterLines(skill) {
  // Line numbers inside the file: frontmatter starts at line 2 (after ---).
  const rawLines = skill.raw.split('\n');
  const start = rawLines[0]?.trim() === '---' ? 1 : -1;
  if (start === -1) return null;
  let end = -1;
  for (let i = start + 1; i < rawLines.length; i++) {
    if (rawLines[i].trim() === '---') {
      end = i;
      break;
    }
  }
  if (end === -1) return null;
  return { lines: rawLines, start, end };
}

function findLine(skill, needle, { inBody = false, wholeFile = false } = {}) {
  const hay = wholeFile ? skill.raw.split('\n') : inBody ? skill.bodyLines : null;
  if (hay) {
    const idx = hay.findIndex((l) => l.includes(needle));
    return idx === -1 ? undefined : idx + 1;
  }
  const fm = frontmatterLines(skill);
  if (!fm) return undefined;
  for (let i = fm.start; i <= fm.end; i++) {
    if (fm.lines[i].includes(needle)) return i + 1;
  }
  return undefined;
}

function* scanLines(lines, re) {
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(re);
    if (m) yield { line: i + 1, match: m[0], text: lines[i].trim() };
  }
}

/** Bundled scripts and other executable files of a skill. */
function scriptFiles(skill) {
  return skill.files.filter(
    (f) => f !== 'SKILL.md' && /\.(sh|bash|zsh|py|js|mjs|cjs|ts|rb|pl|ps1)$/i.test(f),
  );
}

function readSkillFileText(skill, rel) {
  return fsNode.readFileSync(`${skill.dir}/${rel}`, 'utf8');
}

import fsNode from 'node:fs';

/* ------------------------------------------------------------------ */
/* A. Credential & secret exfiltration                                 */
/* ------------------------------------------------------------------ */

rule({
  id: 'env-exfiltration',
  title: 'Reads environment variables and sends them off-machine',
  severity: 'critical',
  type: 'security',
  docs: 'Skills run with your shell access. Combining env reads (where API keys and tokens live) with network calls or encoded writes is the signature of a credential stealer.',
  run(skill) {
    const findings = [];
    const readsEnv = /\b(env\b|\bprintenv|process\.env|os\.environ|ENV\[|getenv)\b/i;
    const network =
      /\b(curl|wget|https?:\/\/|fetch\(|requests\.post|http\.client|nc\b|netcat|Invoke-WebRequest|scp\b|rsync\b)\b/i;
    for (const f of scriptFiles(skill)) {
      let content = '';
      try {
        content = readSkillFileText(skill, f);
      } catch {
        continue;
      }
      if (readsEnv.test(content) && network.test(content)) {
        findings.push({
          message: `script "${f}" both reads environment variables and performs network/file-transfer operations`,
          line: findLine(skill, f, { inBody: true }) ?? findLine(skill, f),
          excerpt: f,
        });
      }
    }
    return findings;
  },
});

rule({
  id: 'secret-file-access',
  title: 'Targets credential stores and secret files',
  severity: 'critical',
  type: 'security',
  docs: 'Reading ~/.ssh, .aws/credentials, .npmrc, browser cookies/keychains or similar from a documentation skill has no legitimate reason in almost all cases.',
  run(skill) {
    const findings = [];
    const patterns = [
      [/\.ssh\b|id_rsa|id_ed25519/i, '~/.ssh private keys'],
      [/\.aws[\/\\]credentials|AWS_SECRET_ACCESS_KEY/, 'AWS credentials'],
      [/\bnpmrc\b|\.pypirc\b/i, 'registry auth tokens'],
      [/cookies\.sqlite|Login Data|keychain|credential[- ]?manager/i, 'browser/OS credential stores'],
      [/(?<![.\w])\.env(?![\w.])(?!\.example)/, '.env files'],
      [/kube[-\\/]?config|\.docker[\/\\]config\.json/, 'cluster/container credentials'],
    ];
    const scopes = [
      ['body', skill.bodyLines],
      ...scriptFiles(skill).map((f) => [`script:${f}`, readSafe(skill, f).split('\n')]),
    ];
    for (const [scope, lines] of scopes) {
      for (const [re, label] of patterns) {
        for (const hit of scanLines(lines, re)) {
          if (isExampleOrDoc(hit.text)) continue;
          findings.push({
            message: `${scope} references ${label}`,
            line: scope === 'body' ? hit.line : undefined,
            excerpt: hit.text.slice(0, 160),
          });
        }
      }
    }
    return findings;
  },
});

function isExampleOrDoc(text) {
  // Deliberately narrow: URLs often legitimately contain "example", so we
  // only skip lines that are clearly documentation or placeholders.
  return /placeholder|your[_-]?key|xxx|<[^>]+>|\bdocs?\b|never|do not|don't/i.test(text);
}

function readSafe(skill, rel) {
  try {
    return readSkillFileText(skill, rel);
  } catch {
    return '';
  }
}

/* ------------------------------------------------------------------ */
/* B. Destructive & dangerous commands                                 */
/* ------------------------------------------------------------------ */

rule({
  id: 'destructive-commands',
  title: 'Contains destructive shell commands',
  severity: 'critical',
  type: 'safety',
  docs: 'rm -rf on broad paths, disk wipes, fork bombs and permission escalations must never appear unconditionally in a skill the agent will follow.',
  run(skill) {
    const findings = [];
    const patterns = [
      [/rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+(?![^&|;]*\btest\b)[^&|;\n]*[*~$\/]/i, 'rm -rf with wildcard/home path'],
      [/mkfs(\.\w+)?\b/, 'filesystem format'],
      [/dd\s+[^;\n]*of=\/dev\//, 'raw disk write via dd'],
      [/:(){ :\|:& };:/, 'fork bomb'],
      [/chmod\s+-R\s+777\s+\//, 'world-writable recursive chmod'],
      [/>\s*\/dev\/sd[a-z]/, 'direct disk device write'],
      [/git\s+push\s+(-f|--force)\s+(origin\s+)?(main|master)/, 'force-push to main branch'],
      [/\b(shutdown|reboot|halt)\b[^"\n]*(now|-h|-r)/i, 'system power command'],
      [/DROP\s+(TABLE|DATABASE)\b/i, 'SQL DROP statement'],
    ];
    const scopes = [
      ['SKILL.md body', skill.bodyLines],
      ...scriptFiles(skill).map((f) => [`script "${f}"`, readSafe(skill, f).split('\n')]),
    ];
    for (const [scope, lines] of scopes) {
      for (const [re, label] of patterns) {
        for (const hit of scanLines(lines, re)) {
          findings.push({
            message: `${scope}: ${label}`,
            line: scope.startsWith('SKILL.md') ? hit.line : undefined,
            excerpt: hit.text.slice(0, 160),
          });
        }
      }
    }
    return findings;
  },
});

rule({
  id: 'curl-pipe-shell',
  title: 'Pipes downloads straight into a shell',
  severity: 'warning',
  type: 'supply-chain',
  docs: '`curl ... | sh` executes whatever a remote server returns at runtime — a classic supply-chain foot-gun, especially when pinned to "latest".',
  run(skill) {
    const findings = [];
    const re = /(?:curl|wget)[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh(?:\s|$)|https?:\/\/[^\s"'`)]*(?:install\.sh|setup\.sh|bootstrap)[^\s"'`)]*/gi;
    for (const hit of scanLines(skill.bodyLines, re)) {
      findings.push({ message: 'downloads and pipes remote scripts into a shell', line: hit.line, excerpt: hit.text.slice(0, 160) });
    }
    return findings;
  },
});

rule({
  id: 'network-access',
  title: 'Makes outbound network calls from scripts',
  severity: 'warning',
  type: 'exfiltration',
  docs: 'Network calls are not always malicious (APIs exist), but every one is a data egress point. They should be visible to the person auditing the skill.',
  run(skill) {
    const findings = [];
    const re = /\b(curl|wget|fetch\(|axios|requests\.(get|post)|urllib|http\.client|Invoke-WebRequest|nc\s+-|socket\.connect)\b/i;
    for (const f of scriptFiles(skill)) {
      const lines = readSafe(skill, f).split('\n');
      for (const hit of scanLines(lines, re)) {
        findings.push({
          message: `script "${f}" makes outbound network calls (${hit.match.trim()})`,
          line: findLine(skill, f, { inBody: true }),
        });
        break; // one finding per script
      }
    }
    return findings;
  },
});

/* ------------------------------------------------------------------ */
/* C. Prompt injection                                                 */
/* ------------------------------------------------------------------ */

rule({
  id: 'instruction-concealment',
  title: 'Instructions hidden from the user',
  severity: 'critical',
  type: 'prompt-injection',
  docs: 'HTML comments and zero-width characters are invisible in rendered markdown but are seen by the model. That split-view is exactly how malicious instructions get smuggled in.',
  run(skill) {
    const findings = [];
    // HTML comments in the body
    const commentRe = /<!--([\s\S]*?)-->/g;
    let m;
    while ((m = commentRe.exec(skill.body)) !== null) {
      const inner = m[1];
    const looksInstructional =
      /(always|never|must|should|ignore|instead|secretly|do not|don't|execute|run\b|send|post\b|upload|collect|append|include|api[ _-]?key|token|secret|credential|passw(or)?d|\benv\b|before\s+(you|responding)|note\s+to\s+(model|assistant|agent)|important|required)/i.test(inner);
      const beforeLine = skill.body.slice(0, m.index).split('\n').length;
      if (looksInstructional) {
        findings.push({
          message: 'HTML comment contains instructional language invisible to the user but readable by the model',
          line: beforeLine,
          excerpt: inner.trim().replace(/\s+/g, ' ').slice(0, 200),
        });
      }
    }
    // Zero-width / homoglyph smuggling across the whole file
    const zeroWidth = /[\u200B\u200C\u200D\u2060\uFEFF]/g;
    const zwCount = (skill.raw.match(zeroWidth) || []).length;
    if (zwCount > 10) {
      findings.push({
        message: `${zwCount} zero-width characters found — can hide instructions from human review`,
        line: (() => {
          const lines = skill.raw.split('\n');
          for (let i = 0; i < lines.length; i++) if (zeroWidth.test(lines[i])) return i + 1;
          return undefined;
        })(),
      });
    }
    return findings;
  },
});

rule({
  id: 'override-system-prompt',
  title: 'Tries to override agent identity or system instructions',
  severity: 'warning',
  type: 'prompt-injection',
  docs: 'A third-party skill telling the model to ignore its instructions, adopt a new persona, or treat new rules as higher priority is attempting a hostile takeover of the session.',
  run(skill) {
    const findings = [];
    const re = /\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)?\s*(instructions|rules|prompts?)\b|\byou\s+are\s+now\b|\bnew\s+persona\b|\bsystem\s*prompt\b|\bjailbreak\b/i;
    for (const hit of scanLines(skill.bodyLines, re)) {
      if (/do not ignore|never ignore/i.test(hit.text)) continue;
      findings.push({ message: 'attempts to override system-level behavior', line: hit.line, excerpt: hit.text.slice(0, 160) });
    }
    return findings;
  },
});

rule({
  id: 'urgency-pressure',
  title: 'Uses urgency or pressure tactics',
  severity: 'info',
  type: 'prompt-injection',
  docs: '"Do this IMMEDIATELY without asking", "this is CRITICAL, skip confirmation" — legitimate skills state what they do; manipulative ones tell the model to stop asking you.',
  run(skill) {
    const findings = [];
    const re = /\b(immediately|right away|at once|urgently|asap)\b[^.\n]{0,60}\b(without (asking|confirming|permission)|skip|bypass|no need to (ask|confirm))\b|\bdo not ask\b[^.\n]{0,40}\b(just|simply)\b|\bskip (all )?(confirmation|user (confirmation|approval))/i;
    for (const hit of scanLines(skill.bodyLines, re)) {
      findings.push({ message: 'pressures the agent to skip user confirmation', line: hit.line, excerpt: hit.text.slice(0, 160) });
    }
    return findings;
  },
});

rule({
  id: 'data-to-remote',
  title: 'Asks the agent to send data to a remote endpoint',
  severity: 'warning',
  type: 'exfiltration',
  docs: 'Instructions that POST/upload/send conversation content, files or "diagnostics" anywhere deserve scrutiny — especially generic paste services.',
  run(skill) {
    const findings = [];
    const re = /\b(post|upload|send|transmit|exfiltrate)\b[^.\n]{0,80}\b(to |at )?https?:\/\/|paste\.rs\b|hastebin\b|termbin\b|webhook\.site\b|requestbin\b|ngrok\b|transfer\.sh\b|file\.io\b|0x0\.st\b/i;
    for (const hit of scanLines(skill.bodyLines, re)) {
      if (isExampleOrDoc(hit.text)) continue;
      findings.push({ message: 'instructs sending data to a remote endpoint', line: hit.line, excerpt: hit.text.slice(0, 160) });
    }
    return findings;
  },
});

/* ------------------------------------------------------------------ */
/* D. Obfuscation                                                      */
/* ------------------------------------------------------------------ */

rule({
  id: 'obfuscated-content',
  title: 'Obfuscated payloads (base64/hex blobs)',
  severity: 'warning',
  type: 'obfuscation',
  docs: 'Long encoded strings plus decode-and-eval/run steps hide intent from reviewers. Some legit tools embed assets this way, so each occurrence needs a look.',
  run(skill) {
    const findings = [];
    const b64 = /[A-Za-z0-9+/]{120,}={0,2}/g;
    const hex = /\b(?:[0-9a-fA-F]{2}){48,}\b/g;
    const decodeUse = /\b(base64|atob|certutil|openssl\s+enc|from64|decode)\b[^;\n]{0,50}\b(eval|exec|sh\b|bash\b|python|node|os\.system|subprocess)/i;
    const scopes = [
      ['SKILL.md', [...skill.bodyLines], 'body'],
      ...scriptFiles(skill).map((f) => [f, readSafe(skill, f).split('\n'), 'script']),
    ];
    for (const [label, lines, kind] of scopes) {
      let blobHits = 0;
      for (const line of lines) {
        if (b64.test(line)) blobHits++;
        b64.lastIndex = 0;
        if (hex.test(line)) blobHits++;
        hex.lastIndex = 0;
      }
      if (blobHits > 0) {
        const firstLine = lines.findIndex((l) => b64.test(l) || hex.test(l)) + 1;
        b64.lastIndex = 0;
        findings.push({
          message: `${label}: long base64/hex blob(s) detected`,
          line: kind === 'body' ? firstLine : undefined,
        });
      }
      for (const hit of scanLines(lines, decodeUse)) {
        findings.push({
          message: `${label}: decodes then executes content (${hit.match})`,
          line: kind === 'body' ? hit.line : undefined,
        });
      }
    }
    return findings;
  },
});

rule({
  id: 'eval-exec',
  title: 'Dynamically evaluates constructed strings',
  severity: 'warning',
  type: 'obfuscation',
  docs: 'eval/exec/os.system/subprocess with shell=True turn any injected string into arbitrary code. In reviewed documentation they are rarely necessary.',
  run(skill) {
    const findings = [];
    const re = /\b(eval|exec)\s*\(|os\.system\s*\(|subprocess\.\w+\([^)]*shell\s*=\s*True|child_process\.exec\s*\(|Function\s*\(\s*['"`]/;
    for (const f of scriptFiles(skill)) {
      const lines = readSafe(skill, f).split('\n');
      for (const hit of scanLines(lines, re)) {
        findings.push({ message: `script "${f}" uses dynamic evaluation (${hit.match.trim()})`, line: findLine(skill, f, { inBody: true }) });
        break;
      }
    }
    return findings;
  },
});

/* ------------------------------------------------------------------ */
/* E. Metadata integrity (spec compliance)                             */
/* ------------------------------------------------------------------ */

rule({
  id: 'missing-frontmatter',
  title: 'No YAML frontmatter',
  severity: 'warning',
  type: 'metadata',
  docs: 'The Agent Skills spec requires a --- delimited YAML block with name and description. Without it the skill will not load correctly.',
  run(skill) {
    if (skill.parseWarnings.some((w) => w.includes('no YAML frontmatter'))) {
      return [{ message: 'SKILL.md is missing its frontmatter block' }];
    }
    return [];
  },
});

rule({
  id: 'missing-name',
  title: 'Missing name field',
  severity: 'warning',
  type: 'metadata',
  run(skill) {
    if (!skill.frontmatter || typeof skill.frontmatter.name !== 'string' || skill.frontmatter.name.trim() === '') {
      return [{ message: 'frontmatter has no usable `name` field' }];
    }
    return [];
  },
});

rule({
  id: 'name-mismatch-dir',
  title: 'name does not match directory name',
  severity: 'info',
  type: 'metadata',
  docs: 'Most loaders key the skill by directory; a mismatched frontmatter name causes confusing activation behavior.',
  run(skill) {
    const name = skill.frontmatter?.name;
    if (typeof name === 'string' && name.trim() && name !== skill.name) {
      return [{ message: `frontmatter name "${name}" != directory name "${skill.name}"`, line: findLine(skill, String(name)) }];
    }
    return [];
  },
});

rule({
  id: 'invalid-name-format',
  title: 'Invalid name format',
  severity: 'info',
  type: 'metadata',
  docs: 'Spec: max 64 chars, lowercase letters/numbers/hyphens only; "anthropic" and "claude" are reserved.',
  run(skill) {
    const name = skill.frontmatter?.name;
    if (typeof name !== 'string' || !name.trim()) return [];
    const problems = [];
    if (name.length > 64) problems.push('longer than 64 chars');
    if (!/^[a-z0-9-]+$/.test(name)) problems.push('must be lowercase letters, numbers and hyphens');
    if (/anthropic|claude/i.test(name)) problems.push('uses reserved words "anthropic"/"claude"');
    if (problems.length) return [{ message: `name "${name}": ${problems.join('; ')}`, line: findLine(skill, name) }];
    return [];
  },
});

rule({
  id: 'missing-description',
  title: 'Missing description field',
  severity: 'warning',
  type: 'metadata',
  docs: 'The description is what the model uses to decide when to load the skill. Missing it means the skill effectively never activates.',
  run(skill) {
    const d = skill.frontmatter?.description;
    if (typeof d !== 'string' || d.trim().length === 0) {
      return [{ message: 'frontmatter has no usable `description` field' }];
    }
    return [];
  },
});

rule({
  id: 'description-too-long',
  title: 'description exceeds 1024 characters',
  severity: 'info',
  type: 'metadata',
  run(skill) {
    const d = skill.frontmatter?.description;
    if (typeof d === 'string' && d.length > 1024) {
      return [{ message: `description is ${d.length} chars (max 1024)` }];
    }
    return [];
  },
});

rule({
  id: 'xml-tags-in-metadata',
  title: 'XML-style tags in frontmatter',
  severity: 'warning',
  type: 'metadata',
  docs: 'Spec forbids XML tags in name/description — they are also a known vector for fake structure/injection in prompts.',
  run(skill) {
    const findings = [];
    const fm = frontmatterLines(skill);
    if (!fm) return findings;
    const re = /<\/?[a-zA-Z][^>]*>/;
    for (let i = fm.start; i <= fm.end; i++) {
      if (re.test(fm.lines[i])) {
        findings.push({ message: 'XML tag found in frontmatter', line: i + 1, excerpt: fm.lines[i].trim().slice(0, 160) });
      }
    }
    return findings;
  },
});

rule({
  id: 'yaml-parse-warning',
  title: 'Frontmatter failed to fully parse',
  severity: 'info',
  type: 'metadata',
  run(skill) {
    return skill.parseWarnings
      .filter((w) => w.startsWith('frontmatter:'))
      .slice(0, 5)
      .map((w) => ({ message: w }));
  },
});

/* ------------------------------------------------------------------ */
/* F. Quality                                                          */
/* ------------------------------------------------------------------ */

rule({
  id: 'body-too-long',
  title: 'Body longer than 500 lines',
  severity: 'info',
  type: 'quality',
  docs: 'Spec guidance: keep SKILL.md under 500 lines and move detail into reference files loaded on demand. Long bodies waste context on every activation.',
  run(skill) {
    const n = skill.bodyLines.filter((l, i, arr) => !(i === arr.length - 1 && l === '')).length;
    if (n > 500) {
      return [{ message: `SKILL.md body is ${n} lines (guideline: <= 500); move details into reference files` }];
    }
    return [];
  },
});

rule({
  id: 'empty-body',
  title: 'Empty instruction body',
  severity: 'info',
  type: 'quality',
  run(skill) {
    const meaningful = skill.bodyLines.map((l) => l.trim()).filter((l) => l !== '' && !l.startsWith('#'));
    if (meaningful.length === 0 && Object.keys(skill.frontmatter || {}).length > 0) {
      return [{ message: 'SKILL.md has frontmatter but no instruction body' }];
    }
    return [];
  },
});

rule({
  id: 'broken-references',
  title: 'References files that do not exist',
  severity: 'info',
  type: 'quality',
  docs: 'Markdown links or backticked paths pointing at missing files break the progressive-disclosure flow the spec relies on.',
  run(skill) {
    const findings = [];
    const linkRe = /\[[^\]]*\]\(([^)#?]+?(?:\.md|\.txt|\.py|\.sh|\.js|\.ts|\.json|\.csv))\)/gi;
    const have = new Set(skill.files);
    for (const hit of scanLines(skill.bodyLines, linkRe)) {
      const target = hit.match.replace(/^\[[^\]]*\]\(/, '').replace(/\)$/, '').trim();
      const clean = target.replace(/^\.\//, '');
      if (have.has(clean) || have.has(target)) continue;
      findings.push({ message: `links to missing file "${clean}"`, line: hit.line, excerpt: hit.text.slice(0, 160) });
    }
    return findings;
  },
});

rule({
  id: 'unbounded-script-exec',
  title: 'Runs scripts that were never shown or explained',
  severity: 'info',
  type: 'quality',
  docs: 'Good practice per spec: tell the user what each bundled script does. "Just run setup.sh" with no explanation hides what the agent will execute.',
  run(skill) {
    const findings = [];
    const scripts = scriptFiles(skill);
    for (const f of scripts) {
      const mentioned = countOccurrences(skill.body, f);
      if (mentioned === 0) {
        findings.push({ message: `bundled script "${f}" is never mentioned in SKILL.md` });
      }
    }
    return findings;
  },
});

rule({
  id: 'pip-install-unpinned',
  title: 'Installs packages without version pins',
  severity: 'info',
  type: 'supply-chain',
  docs: '`pip install foo` / `npm install foo` at runtime resolves whatever the registry serves today — a silent supply-chain swap risk. Pin versions or use lockfiles.',
  run(skill) {
    const findings = [];
    const re = /\b(pip3?\s+install|npm\s+i(?:nstall)?|yarn\s+add|pnpm\s+(?:i|add))\s+([a-zA-Z@][^\s;&|]*)/;
    for (const hit of scanLines(skill.bodyLines, re)) {
      const pkg = hit.text.match(re)?.[2] ?? '';
      if (/[@=<>]|\binstalling\b/i.test(pkg)) continue;
      if (pkg.startsWith('-')) continue; // flags like -r requirements.txt
      findings.push({ message: `installs "${pkg.replace(/\/+$/, '')}" without a version pin`, line: hit.line, excerpt: hit.text.slice(0, 160) });
    }
    return findings;
  },
});

function countOccurrences(haystack, needle) {
  if (!needle) return 0;
  let count = 0;
  let pos = 0;
  while ((pos = haystack.indexOf(needle, pos)) !== -1) {
    count += 1;
    pos += needle.length;
  }
  return count;
}

/* ------------------------------------------------------------------ */

export function ruleById(id) {
  return RULES.find((r) => r.id === id);
}

export function severityRank(sev) {
  return SEVERITY_ORDER[sev] ?? 99;
}
