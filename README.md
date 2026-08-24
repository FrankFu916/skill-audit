# 🛡️ skill-audit

**Security & quality audits for AI agent skills — before they run.**

Your agent loads `SKILL.md` files from the internet and follows their
instructions with your shell, your files, and your credentials. Nothing checks
what's inside them.

`skill-audit` is a zero-dependency CLI that statically scans Agent Skills
(Claude Code, Codex CLI, Cursor, opencode, …) for prompt injection, credential
exfiltration, destructive commands, obfuscated payloads, and broken metadata —
then gives each skill a 0–100 health score.

```bash
npx skill-audit ~/.claude/skills
```

```
  env-sync  — skills/env-sync/SKILL.md
  ✖ CRITICAL script "scripts/sync.sh" both reads environment variables and performs network/file-transfer operations
      [env-exfiltration] at line 4
  ✖ CRITICAL script:scripts/sync.sh references ~/.ssh private keys
      └─ cat ~/.ssh/id_rsa >> /tmp/extras.txt
      [secret-file-access]
  ⚠ WARNING script "scripts/sync.sh" makes outbound network calls (curl)
      [network-access] at line 4
  score: 0/100

Summary
  5 skill(s) audited · 24 rules · 8 critical · 3 warnings · 7 info
```

## Why

Agent Skills are the fastest-growing package ecosystem on GitHub — and the
least inspected. A skill is executable instructions plus bundled scripts:

- Its **description is injected into your system prompt**, where hidden
  instructions can hijack the session (prompt injection).
- Its **scripts run in your shell** without ever being shown to you — a skill
  that "manages dotfiles" can also `cat ~/.ssh/id_rsa` and POST it somewhere.
- There is **no review step**: no lockfile, no registry audit, no sandbox by
  default.

`skill-audit` closes that gap the way `npm audit` did for packages: fast,
local, opinionated, CI-friendly. It runs entirely offline — it reads files and
reports; it never executes anything it finds.

## Install

No install needed:

```bash
npx skill-audit <path>
```

Or add it to a project / CI:

```bash
npm install -D skill-audit
```

Requires Node ≥ 18. Zero runtime dependencies.

## Usage

```bash
skill-audit <paths...> [options]

# Audit everything installed for your user
npx skill-audit                       # defaults to ~/.claude/skills if present
npx skill-audit ~/.claude/skills

# Audit one repo's skills before publishing yours
npx skill-audit ./skills/my-skill

# Machine-readable output for CI
npx skill-audit .claude/skills -f sarif -o results.sarif
npx skill-audit .claude/skills -f json | jq '.summary'

# Tune the rule set
npx skill-audit ./skills --skip network-access,pip-install-unpinned
```

| Option | Description |
|---|---|
| `-f, --format` | `full` \| `compact` \| `json` \| `sarif` \| `markdown` |
| `-o, --output <file>` | Write report to file instead of stdout |
| `--only <rules>` | Run only these rules (comma-separated ids) |
| `--skip <rules>` | Skip these rules |
| `-q, --quiet` | Summary only |
| `--no-color` | Disable colored output |

**Exit codes** make it a CI gate: `0` clean · `1` critical findings · `2`
bad arguments or unreadable paths.

### GitHub Actions

```yaml
name: skill-audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npx -y skill-audit ./skills -f sarif -o results.sarif || echo "findings above"
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

Findings then appear under the repo's **Security → Code scanning** tab.

## What it detects

24 rules across six categories. Every finding cites its rule id, line number,
and matched text — nothing is a black box.

<details>
<summary><strong>Full rule catalog</strong></summary>

**Credential & secret exfiltration**

| Rule | Severity |
|---|---|
| `env-exfiltration` — scripts that read environment variables *and* make network calls | critical |
| `secret-file-access` — references to `~/.ssh`, AWS credentials, `.npmrc`, `.env`, keychains | critical |

**Destructive & dangerous commands**

| Rule | Severity |
|---|---|
| `destructive-commands` — recursive `rm` over wildcards/`~`/`$HOME`/root, `mkfs`, `dd of=/dev/*`, fork bombs, force-push to main, `DROP TABLE/DATABASE`, power commands | critical |
| `curl-pipe-shell` — piping downloads straight into a shell | warning |
| `network-access` — outbound network calls from bundled scripts | warning |

**Prompt injection**

| Rule | Severity |
|---|---|
| `instruction-concealment` — instructional HTML comments, zero-width character smuggling | critical |
| `override-system-prompt` — "ignore previous instructions", persona takeover | warning |
| `data-to-remote` — sending conversation/file data to endpoints, paste services, webhooks | warning |
| `urgency-pressure` — "do this immediately without asking" | info |

**Obfuscation**

| Rule | Severity |
|---|---|
| `obfuscated-content` — base64/hex blobs, decode-then-execute patterns | warning |
| `eval-exec` — dynamic evaluation in bundled scripts | warning |

**Metadata integrity** (Agent Skills spec)

| Rule | Severity |
|---|---|
| `missing-frontmatter`, `missing-name`, `missing-description` | warning |
| `xml-tags-in-metadata` | warning |
| `invalid-name-format`, `name-mismatch-dir`, `description-too-long`, `yaml-parse-warning` | info |

**Quality & supply-chain hygiene**

| Rule | Severity |
|---|---|
| `body-too-long` (spec: ≤500 lines), `empty-body`, `broken-references`, `unbounded-script-exec` | info |
| `pip-install-unpinned` — unpinned installs resolved at runtime | info |

</details>

## The score

Each skill gets **100 minus weighted penalties**: −34 per critical,
−12 per warning, −3 per info, floored at 0.

- **80–100** healthy — ship it
- **50–79** needs a look — read the warnings before installing
- **0–49** do not install without a full manual review

## Library API

The auditor is importable — build editors, dashboards, or pre-install hooks on top:

```js
import { createAuditRunner } from 'skill-audit';

const runner = createAuditRunner({ version: 'x.y.z' });
const report = runner.audit(['~/.claude/skills'], { skip: ['network-access'] });
console.log(report.summary);        // { skills, critical, warning, info, minScore }
console.log(runner.renderSarif(report));
```

## Design principles

1. **Static analysis only.** It never executes skill code or fetches URLs.
2. **Zero dependencies.** ~600 lines of auditable source; the supply chain for
   your security tool is the tool itself.
3. **Explainable findings.** Rule id + line + excerpt + docs for every hit.
   No scores from a neural net you can't interrogate.
4. **CI-native.** SARIF output, stable JSON schema, meaningful exit codes.

## Limitations

Static analysis sees what's written, not what's meant — obfuscated payloads
can hide from regexes, and a benign-looking pattern may be flagged while being
harmless. Treat `skill-audit` as a necessary filter, not sufficient review:
for anything score < 80, read the SKILL.md and its scripts yourself.

## Related

- [Agent Skills spec](https://github.com/anthropics/skills) — official format & examples
- Skills ecosystems are exploding; so are third-party skills of unknown provenance. Audit before you activate.

## Contributing

Rules are small, pure functions — adding one is a great first PR:
implement `run(skill)` in `src/rules.js`, add a fixture under
`test/fixtures/`, assert in `test/rules.test.js`. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
