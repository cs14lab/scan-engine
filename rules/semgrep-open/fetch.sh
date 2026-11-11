#!/usr/bin/env bash
# Refreshes the openly licensed Semgrep rules that ts-e1 runs beside our own
# (rules/semgrep). Only rule files and licences are copied, at pinned commits.
#
#   gitlab-lgpl/  GitLab sast-rules, rules/lgpl only (LGPL-3.0). Its other
#                 folders are not usable: rules/gitlab is GitLab EE-licensed,
#                 rules/lgpl-cc carries the Commons Clause.
#   0xdea/        0xdea/semgrep-rules (MIT), C and C++.
#
# Never add the Semgrep Registry (p/*, --config auto, semgrep/semgrep-rules):
# its licence allows internal use only, not use as a service, paid or free.
set -euo pipefail
GITLAB_SHA=c30d438ba620cd19c939ad9cbe91ae1aa0ce659d
OXDEA_SHA=b9942606d3543e3145a95332e6543fb79a01af00
HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

mkdir "$TMP/gl" "$TMP/ox"
curl -fsSL "https://gitlab.com/gitlab-org/security-products/sast-rules/-/archive/$GITLAB_SHA/sast-rules-$GITLAB_SHA.tar.gz?path=rules/lgpl" \
  | tar -xz -C "$TMP/gl" --strip-components=3
curl -fsSL "https://codeload.github.com/0xdea/semgrep-rules/tar.gz/$OXDEA_SHA" | tar -xz -C "$TMP/ox" --strip-components=1

copy_rules() {   # from, to
  rm -rf "$2"; mkdir -p "$2"
  (cd "$1" && find . -type f \( -name '*.yml' -o -name '*.yaml' \) -print0) |
    while IFS= read -r -d '' f; do mkdir -p "$2/$(dirname "$f")"; cp "$1/$f" "$2/$f"; done
}
copy_rules "$TMP/gl" "$HERE/gitlab-lgpl"
cp "$TMP/gl/LICENSE" "$HERE/gitlab-lgpl/LICENSE"
copy_rules "$TMP/ox/rules" "$HERE/0xdea"
rm -rf "$HERE/0xdea/noisy"   # its authors mark these as high in false positives
cp "$TMP/ox/LICENSE" "$HERE/0xdea/LICENSE"
echo "gitlab-lgpl: $(find "$HERE/gitlab-lgpl" -name '*.y*ml' | wc -l) rule files; 0xdea: $(find "$HERE/0xdea" -name '*.y*ml' | wc -l)"
