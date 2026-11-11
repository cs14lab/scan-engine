# Openly licensed rules for ts-e1

Engine ts-e1 runs two rule sets, and only these two:

- `rules/semgrep`: TrustScan's own rules.
- `rules/semgrep-open` (this folder): third-party rules whose licences allow
  us to run them on customers' code, free or paid, and to publish them.

| Folder | Source | Commit | Licence | Languages |
|---|---|---|---|---|
| `gitlab-lgpl/` | [GitLab sast-rules](https://gitlab.com/gitlab-org/security-products/sast-rules), `rules/lgpl` only | `c30d438b` | LGPL-3.0 (`gitlab-lgpl/LICENSE`) | Java, JavaScript, Kotlin, Objective-C, Swift |
| `0xdea/` | [0xdea/semgrep-rules](https://github.com/0xdea/semgrep-rules), without `noisy/` | `b9942606` | MIT (`0xdea/LICENSE`) | C, C++ |

The files are unmodified copies. Refresh them with `./fetch.sh` (pinned
commits inside), then check they load:

    semgrep --validate --metrics=off --config rules/semgrep-open --config rules/semgrep

## Not allowed here

Checked 11 Nov 2026:

- **The Semgrep Registry** (`--config auto`, `p/...`, `semgrep/semgrep-rules`):
  "You may use the rules only for your own internal business purposes … not
  … make them available to others as a service." It has no exception for free use.
- **GitLab `rules/gitlab`**: GitLab Enterprise Edition licence.
- **GitLab `rules/lgpl-cc`** and **Opengrep's rules**: carry the Commons Clause.
- **elttam/semgrep-rules**: MIT-labelled, but its paths mirror the Semgrep
  Registry's; its provenance needs checking first.

## Gaps

No third-party rules cover Python, Go, PHP, Ruby or C# yet. Python has only our
own rules. Python and Go are the next to fill, with rules we write or an
openly licensed engine.
