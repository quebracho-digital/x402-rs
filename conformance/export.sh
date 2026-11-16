#!/usr/bin/env bash
# Regenerates conformance/vectors/*.json from the PHP library quebracho/x402.
#
#   conformance/export.sh                          # the library at the commit pinned in the Dockerfile
#   X402_REF=<commit> conformance/export.sh        # another commit of the public repository
#   X402_LIB=/path/to/x402 conformance/export.sh   # a local checkout instead (its vendor/ installed)
#
# Needs only Docker: the image is built from conformance/Dockerfile (PHP 8.3 + gmp + the library).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
ref="${X402_REF:-$(sed -n 's/^ARG X402_REF=//p' "$here/Dockerfile")}"
image="x402-rs-conformance:${ref:0:12}"
docker build --quiet -t "$image" --build-arg X402_REF="$ref" "$here" >/dev/null

mount=()
commit="${ref:0:7}"
if [ -n "${X402_LIB:-}" ]; then
  lib="$(cd "$X402_LIB" && pwd)"
  commit="$(git -C "$lib" rev-parse --short HEAD)"
  [ -z "$(git -C "$lib" status --porcelain)" ] || commit="$commit-dirty"
  mount=(-v "$lib":/x402:ro)
fi

for script in export.php scenarios.php facilitator.php; do
  docker run --rm --user "$(id -u):$(id -g)" \
    -e X402_COMMIT="$commit" "${mount[@]}" -v "$here":/out \
    "$image" /out/"$script" /x402 /out/vectors
done
