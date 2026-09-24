#!/usr/bin/env bash
# Runs terraform with a freshly minted GitHub OIDC token.
#
# The providers can fetch their own token from ARM_OIDC_REQUEST_URL, and they
# cache what they get. On the second live run of this lab the azuread provider
# authenticated successfully during apply and then failed the same credential
# minutes later with AADSTS700213, having reported "failed to get auth from
# auth cache" on the run before -- both consistent with a stale or negative
# cache entry rather than with a wrong credential.
#
# Passing ARM_OIDC_TOKEN takes precedence over the request URL in the
# providers' discovery order, so every invocation gets a token minted seconds
# earlier and nothing consults a cache. It also means an authentication
# failure is attributable: if the exchange fails it fails here, before
# terraform starts, rather than part-way through an apply.
set -euo pipefail

: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?not running in a job with id-token: write}"
: "${ACTIONS_ID_TOKEN_REQUEST_URL:?not running in a job with id-token: write}"

token=$(curl -sS --fail \
  -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" \
  | jq -r '.value')

if [ -z "$token" ] || [ "$token" = "null" ]; then
  echo "GitHub returned no OIDC token. Terraform would fail on every provider, so stopping here where the cause is visible." >&2
  exit 1
fi

export ARM_OIDC_TOKEN="$token"
exec terraform "$@"
