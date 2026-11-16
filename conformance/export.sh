#!/usr/bin/env bash
# Regenerates conformance/vectors/*.json from the PHP library quebracho/x402.
#
#   X402_LIB=~/Proyects/x402-lib conformance/export.sh
#
# The library needs PHP >= 8.3 with gmp and sodium, and its vendor/ installed.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
lib="$(cd "${X402_LIB:-$HOME/Proyects/x402-lib}" && pwd)"
image="${X402_PHP_IMAGE:-x402-php83-full}"
commit="$(git -C "$lib" rev-parse --short HEAD)"
if [ -n "$(git -C "$lib" status --porcelain)" ]; then
  commit="$commit-dirty"
fi

docker run --rm --user "$(id -u):$(id -g)" --entrypoint php \
  -e X402_COMMIT="$commit" \
  -v "$lib":/x402:ro -v "$here":/out \
  "$image" /out/export.php /x402 /out/vectors
docker run --rm --user "$(id -u):$(id -g)" --entrypoint php \
  -e X402_COMMIT="$commit" \
  -v "$lib":/x402:ro -v "$here":/out \
  "$image" /out/scenarios.php /x402 /out/vectors
docker run --rm --user "$(id -u):$(id -g)" --entrypoint php \
  -e X402_COMMIT="$commit" \
  -v "$lib":/x402:ro -v "$here":/out \
  "$image" /out/facilitator.php /x402 /out/vectors
