# Changelog

All notable changes to this project will be documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-08-24

### Added

- Initial release: static security & quality audit for AI agent skills
  (`SKILL.md` packages).
- 24 rules across six categories: credential exfiltration, destructive
  commands, prompt injection, obfuscation, metadata integrity (Agent Skills
  spec), and quality/supply-chain hygiene.
- Recursive skill discovery with `node_modules`/VCS noise skipping; audits
  single `SKILL.md` files too.
- Bundled-script inspection: rules read the scripts a skill ships, not just
  its markdown.
- 0–100 health score per skill (−34 critical / −12 warning / −3 info).
- Output formats: human-readable terminal report, compact, JSON (stable
  schema), SARIF 2.1.0 for GitHub code scanning, Markdown for PRs.
- CLI: `--format`, `--output`, `--only`, `--skip`, `--quiet`, `--no-color`;
  CI-friendly exit codes (0 clean / 1 critical / 2 usage-error).
- Zero runtime dependencies; Node ≥ 18.
- Library API: `createAuditRunner`, plus direct exports of
  `audit`, `RULES`, `discoverSkills`, `parseYaml`, renderers.
- 34 tests (unit + end-to-end) and five demo fixtures including a realistic
  credential-stealing skill.

### Fixed

- Calibrated against the official [anthropics/skills](https://github.com/anthropics/skills)
  corpus (19 real skills): `env-exfiltration` no longer fires on tool flags
  like `-env:UserInstallation=` or bare URLs in XML; `destructive-commands`
  only flags *recursive* deletes (`rm -r/-rf`) over wildcards/`~`/`$HOME`/root,
  so ordinary `rm -f file` cleanup passes; all body-finding line numbers are
  now absolute file lines (SARIF regions were off by the frontmatter height).
