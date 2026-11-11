# Own rules

Registry rules are what every competitor runs, including the free tier. These
are the ones written from defects observed in real code that no registry rule
reported — they are the only part of the detection stack a competitor cannot
`pip install`.

Every rule in this directory must:

1. **Come from a confirmed miss.** A finding a customer confirmed as real, that
   no engine in the union reported. The rule's `metadata.provenance` records
   which one.
2. **Carry a message that explains the exploit**, not the pattern. "Use
   `Path(name).name`" is worth more than "user input reaches a file path".
3. **Declare sanitizers.** A taint rule without `pattern-sanitizers` is a
   false-positive generator, and this directory exists to add signal.
4. **Have a fixture beside it** — `foo.yaml` is tested by `foo.py`, which is
   where `semgrep --test` looks — carrying both a vulnerable case (`ruleid:`)
   and a sanitized one (`ok:`), so the run proves the detection *and* the
   sanitizer. A taint rule whose sanitizers are untested is a rule that will be
   turned off by the first person it annoys.

ts-e1 runs them with the openly licensed rules in `rules/semgrep-open`, never
the Semgrep Registry packs (their licence allows internal use only):

    semgrep scan --metrics=off --config ./rules/semgrep --config ./rules/semgrep-open --json ...

Test them:

    semgrep --test --config rules/semgrep rules/semgrep

Validate them before committing — a rule that fails to load contributes nothing
and says nothing when passed in a `--config` directory:

    semgrep --validate --config rules/semgrep
