# Roadmap

Dates are directional. Anything here can be reshaped by user feedback —
[open an issue](https://github.com/FrankFu916/skill-audit/issues) if you need
something on this list sooner.

## v0.2 — trust & ecosystem (near term)

- [ ] **`--fix` metadata mode** — auto-repair spec violations (name format,
      missing description, dir mismatch) with a diff preview.
- [ ] **Baseline & ignore files** — `.skill-auditrc` with per-path rule
      suppressions and inline `<!-- skill-audit-ignore-next-line -->`, so
      legit tools stop re-flagging known-good patterns.
- [ ] **Skill registry allow/deny lists** — pin the hashes of skills you
      vetted; CI fails if anything changed since (`supply-chain drift
      detection`, the lockfile skill ecosystems don't have).
- [ ] **VS Code extension** — findings inline in SKILL.md editors.

## v0.3 — analysis depth

- [ ] **Data-flow taint tracking** — follow "read env → transform → write to
      network" across statements instead of line-level pattern matching;
      kills remaining false positives, catches split-payload exfiltration.
- [ ] **AST-based JS/TS script parsing** for obfuscation detection beyond
      regex (string-array deobfuscation, control-flow flattening tells).
- [ ] **Behavioral summaries in plain language** — "this skill reads your SSH
      keys and uploads them to relay.envsync.dev" as a one-line risk sentence
      per finding.
- [ ] **Prompt-injection eval harness** — run a skill's description against a
      small local model to score injection susceptibility.

## v0.4 — teams & registries

- [ ] **Hosted index of audited skills** — community registry where scores,
      maintainers, and review status are browsable before install; CLI shows
      community score next to local score.
- [ ] **GitHub App** — auto-comment audit reports on PRs that add/modify
      skills, org-wide policy enforcement ("no criticals in merged skills").
- [ ] **SLSA-style provenance for skill authors** — sign your skill releases;
      `skill-audit verify` checks signatures + audit history.
- [ ] **Editor integrations** beyond VS Code (Cursor, Zed).

## Non-goals

- Runtime sandboxing / execution enforcement — that's a different product
  (see: runtime firewalls); we stay static, fast, and dependency-free.
- Telemetry of any kind. Audits never phone home.
