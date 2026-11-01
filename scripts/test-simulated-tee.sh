#!/usr/bin/env bash
# End-to-end smoke and tamper-refusal verification for the local Docker
# simulated TEE (docker-compose.simulated-tee.yml): simulated Confidential
# Space tokens, checked by the token verifier before key release (ADR 0004).
set -euo pipefail

COMPOSE_FILE="docker-compose.simulated-tee.yml"
TENANT_ID="6f2c8a2e-1111-4222-8333-444455556666"
JWT_SECRET="simulated-tee-local-jwt-secret-32b!!"

cleanup() {
  local status=$?
  if [[ ${status} -ne 0 ]]; then
    docker compose -f "${COMPOSE_FILE}" logs --tail 20 >&2 || true
  fi
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

b64url() {
  openssl base64 -e -A | tr '+/' '-_' | tr -d '='
}

mint_jwt() {
  local tid="$1"
  local exp=$(( $(date +%s) + 3600 ))
  local header='{"alg":"HS256","typ":"JWT"}'
  local claims
  claims=$(printf '{"sub":"sim-user","tid":"%s","iss":"quackxide.local","aud":"quackxide-api","exp":%d,"adm":false,"typ":"access"}' "${tid}" "${exp}")
  local signing_input
  signing_input="$(printf '%s' "${header}" | b64url).$(printf '%s' "${claims}" | b64url)"
  local sig
  sig=$(printf '%s' "${signing_input}" | openssl dgst -sha256 -hmac "${JWT_SECRET}" -binary | b64url)
  printf '%s.%s' "${signing_input}" "${sig}"
}

wait_for_http() {
  local url="$1"
  local attempts=30
  for ((i=1; i<=attempts; i++)); do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "ERROR: timed out waiting for ${url}" >&2
  return 1
}

QUERY='{"connector":"quickbooks","sql":"SELECT currency, COUNT(*) AS n FROM quickbooks GROUP BY currency ORDER BY currency"}'

query_status() {
  curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:8080/api/v1/query" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d "${QUERY}"
}

# Restart sim-attestation with one claim changed and expect queries to fail closed.
expect_tamper_refused() {
  local name="$1" var="$2" value="$3"
  env "${var}=${value}" docker compose -f "${COMPOSE_FILE}" up -d --force-recreate sim-attestation >/dev/null
  # Without this, a 503 could mean the service is not up yet rather than a refusal.
  wait_for_http "http://127.0.0.1:8070/healthz"
  local code
  code=$(query_status)
  if [[ "${code}" != "503" ]]; then
    echo "ERROR: expected HTTP 503 with ${name}, got ${code}" >&2
    exit 1
  fi
  echo "    ${name} refused with HTTP 503."
}

echo "==> [1/5] Building all images; starting sim-attestation and key-release-service..."
# Build every image now, so later stages never start one built from older code.
docker compose -f "${COMPOSE_FILE}" build
docker compose -f "${COMPOSE_FILE}" up -d sim-attestation key-release-service
wait_for_http "http://127.0.0.1:8070/healthz"
wait_for_http "http://127.0.0.1:8090/healthz"

echo "==> [2/5] Enrolling the demo tenant's key with key-release-service..."
PRIVATE_KEY_B64=$(openssl rand -base64 32)
ENROLL_JSON=$(curl -fsS -X PUT "http://127.0.0.1:8090/v1/keys" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"${TENANT_ID}\",\"private_key_b64\":\"${PRIVATE_KEY_B64}\"}")
TENANT_PUBKEY_B64=$(printf '%s' "${ENROLL_JSON}" | sed -n 's/.*"public_key_b64":"\([^"]*\)".*/\1/p')
if [[ -z "${TENANT_PUBKEY_B64}" ]]; then
  echo "ERROR: failed to extract public_key_b64 from key-release-service response: ${ENROLL_JSON}" >&2
  exit 1
fi

echo "==> [3/5] Starting enclave-api and sealing the synthetic QuickBooks fixture into its vault..."
DEMO_TENANT_ID="${TENANT_ID}" \
DEMO_TENANT_PUBLIC_KEY_B64="${TENANT_PUBKEY_B64}" \
  docker compose -f "${COMPOSE_FILE}" up -d enclave-api
wait_for_http "http://127.0.0.1:8080/healthz"

TOKEN=$(mint_jwt "${TENANT_ID}")

echo "==> [4/5] Verifying the attestation token and the confidential query happy path..."
NONCE_B64=$(openssl rand -base64 32)
ATTEST_RESP=$(curl -fsS -G "http://127.0.0.1:8080/api/v1/attestation" --data-urlencode "nonce_b64=${NONCE_B64}")
if ! printf '%s' "${ATTEST_RESP}" | grep -q '"token":"ey'; then
  echo "ERROR: expected a token in /api/v1/attestation response: ${ATTEST_RESP}" >&2
  exit 1
fi

QUERY_RESP=$(curl -fsS -X POST "http://127.0.0.1:8080/api/v1/query" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "${QUERY}")
if ! printf '%s' "${QUERY_RESP}" | grep -q '"rows"'; then
  echo "ERROR: expected result rows in query response: ${QUERY_RESP}" >&2
  exit 1
fi
echo "    Happy path verified (token-gated key release and query)."

echo "==> [5/5] Verifying fail-closed refusal of tampered tokens..."
expect_tamper_refused "a debug image" SIM_TOKEN_DBGSTAT enabled
expect_tamper_refused "an unlisted image digest" SIM_TOKEN_IMAGE_DIGEST "sha256:$(printf '0%.0s' {1..64})"
expect_tamper_refused "non-TDX hardware" SIM_TOKEN_HWMODEL GCP_AMD_SEV

docker compose -f "${COMPOSE_FILE}" up -d --force-recreate sim-attestation >/dev/null
wait_for_http "http://127.0.0.1:8070/healthz"
CODE=$(query_status)
if [[ "${CODE}" != "200" ]]; then
  echo "ERROR: expected HTTP 200 after restoring default claims, got ${CODE}" >&2
  exit 1
fi
echo "    Default claims accepted again after the simulator restarted with a new key."

echo "==> All simulated TEE Docker verification checks passed."
