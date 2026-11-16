# The PHP library quebracho/x402 at a fixed commit, ready to export conformance vectors.
# Anyone can rebuild it: the library is public, the commit is pinned, nothing comes from the host.
#
#   docker build -t x402-rs-conformance --build-arg X402_REF=<commit> conformance/
#
# PHP 8.3 (the library's minimum) with gmp; sodium ships with the official image.
FROM php:8.3.36-cli

RUN apt-get update \
 && apt-get install -y --no-install-recommends git unzip libgmp-dev \
 && docker-php-ext-install gmp \
 && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2.8 /usr/bin/composer /usr/bin/composer

ARG X402_REF=592f1e6473e63180f65753e196935a81b4708f8e
RUN git clone https://github.com/quebracho-digital/x402.git /x402 \
 && git -C /x402 checkout --quiet "$X402_REF" \
 && composer --working-dir=/x402 install --no-interaction --no-progress --quiet

ENTRYPOINT ["php"]
