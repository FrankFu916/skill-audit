# Contributing to skill-audit

Thanks for helping make third-party agent skills safer!

## Adding a rule (best first PR)

Rules live in `src/rules.js`. A rule is a plain object:

```js
rule({
  id: 'my-new-rule',              // kebab-case, unique
  title: 'One-line summary',
  severity: 'critical',           // critical | warning | info
  type: 'security',               // security | safety | exfiltration | prompt-injection |
                                  // obfuscation | supply-chain | metadata | quality
  docs: 'Why this matters — shown in SARIF help text.',
  run(skill) {                    // pure function; never throws
    return [
      // one entry per finding
      { message: 'what is wrong', line: 12, excerpt: 'matched text' },
    ];
  },
});
```

`skill` gives you:

| Field | Meaning |
|---|---|
| `frontmatter` | parsed YAML block |
| `body` / `bodyLines` | instruction body after frontmatter |
| `files` | every file shipped next to SKILL.md (relative paths) |
| `raw` | full file text |

To read a bundled script: `readSkillFileText(skill, relPath)`.

Then:

1. Add a fixture under `test/fixtures/` that triggers your rule (and one that
   must **not** trigger it — false positives are the enemy).
2. Assert in `test/rules.test.js`.
3. Add the rule id + severity to the README catalog.

Run `npm test` — it must stay green.

## False-positive reports

Open an issue with: the rule id, the exact line flagged, and why it's
legitimate. We tune aggressively; noisy rules get narrowed or split.

## Local development

```bash
npm test                 # full suite
npm run demo             # audit the demo fixtures
node bin/skill-audit.js <path> -f compact   # manual runs
```

## Principles

- Static analysis only — no network, no execution.
- Zero runtime dependencies — don't add any without discussing first.
- Every finding must be explainable from the source line it cites.
