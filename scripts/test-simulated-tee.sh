#!/usr/bin/env bash
# End-to-end smoke and tamper-refusal verification for the local Docker
# Simulated AMD SEV-SNP TEE topology (docker-compose.simulated-tee.yml).
set -euo pipefail

COMPOSE_FILE="docker-compose.simulated-tee.yml"
TENANT_ID="6f2c8a2e-1111-4222-8333-444455556666"
JWT_SECRET="simulated-tee-local-jwt-secret-32b!!"

cleanup() {
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

echo "==> [1/5] Building and starting fake-gcs and key-release-service..."
docker compose -f "${COMPOSE_FILE}" up -d --build fake-gcs key-release-service

echo "==> [2/5] Creating 'quackxide-vault' bucket in fake-gcs and enrolling demo tenant..."
curl -fsS -X POST "http://127.0.0.1:4443/storage/v1/b?project=quackxide-sim" \
  -H "Content-Type: application/json" \
  -d '{"name":"quackxide-vault"}' >/dev/null

ENROLL_JSON=$(curl -fsS -X POST "http://127.0.0.1:8090/v1/key-release/tenants" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"${TENANT_ID}\"}")

TENANT_PUBKEY_B64=$(printf '%s' "${ENROLL_JSON}" | sed -n 's/.*"public_key_b64":"\([^"]*\)".*/\1/p')
if [[ -z "${TENANT_PUBKEY_B64}" ]]; then
  echo "ERROR: failed to extract public_key_b64 from key-release-service response: ${ENROLL_JSON}" >&2
  exit 1
fi

echo "==> [3/5] Starting enclave-api and sealing synthetic QuickBooks fixture into fake-gcs..."
DEMO_TENANT_ID="${TENANT_ID}" \
DEMO_TENANT_PUBLIC_KEY_B64="${TENANT_PUBKEY_B64}" \
  docker compose -f "${COMPOSE_FILE}" up -d enclave-api

wait_for_http "http://127.0.0.1:8080/healthz"

TOKEN=$(mint_jwt "${TENANT_ID}")

echo "==> [4/5] Verifying public attestation quote and confidential query happy path..."
ATTEST_RESP=$(curl -fsS "http://127.0.0.1:8080/api/v1/attestation?nonce=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
if ! printf '%s' "${ATTEST_RESP}" | grep -q '"report_b64"'; then
  echo "ERROR: expected report_b64 in /api/v1/attestation response: ${ATTEST_RESP}" >&2
  exit 1
fi

QUERY_RESP=$(curl -fsS -X POST "http://127.0.0.1:8080/api/v1/query" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"connector":"quickbooks","sql":"SELECT currency, COUNT(*) AS n FROM quickbooks GROUP BY currency ORDER BY currency"}')

if ! printf '%s' "${QUERY_RESP}" | grep -q '"enclave_signature"'; then
  echo "ERROR: expected enclave_signature in query response: ${QUERY_RESP}" >&2
  exit 1
fi
echo "    Happy path verified (signed enclave response received)."

echo "==> [5/5] Verifying fail-closed tamper refusal (MEASUREMENT mismatch & DEBUG=1)..."
TAMPERED_MEAS=$(printf 'ff%.0s' {1..96})
SIMULATED_SNP_MEASUREMENT_HEX="${TAMPERED_MEAS}" \
  docker compose -f "${COMPOSE_FILE}" up -d --force-recreate enclave-api
wait_for_http "http://127.0.0.1:8080/healthz"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:8080/api/v1/query" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"connector":"quickbooks","sql":"SELECT COUNT(*) FROM quickbooks"}')
if [[ "${HTTP_CODE}" != "503" ]]; then
  echo "ERROR: expected HTTP 503 on tampered MEASUREMENT, got ${HTTP_CODE}" >&2
  exit 1
fi
echo "    MEASUREMENT mismatch refused with HTTP 503."

SIMULATED_SNP_DEBUG="true" \
  docker compose -f "${COMPOSE_FILE}" up -d --force-recreate enclave-api
wait_for_http "http://127.0.0.1:8080/healthz"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:8080/api/v1/query" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"connector":"quickbooks","sql":"SELECT COUNT(*) FROM quickbooks"}')
if [[ "${HTTP_CODE}" != "503" ]]; then
  echo "ERROR: expected HTTP 503 on GuestPolicy::DEBUG=1, got ${HTTP_CODE}" >&2
  exit 1
fi
echo "    GuestPolicy::DEBUG=1 refused with HTTP 503."

echo "==> All Simulated TEE Docker verification checks passed."
