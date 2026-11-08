#!/usr/bin/env bash
# End-to-end verification on the local Docker simulated TEE
# (docker-compose.simulated-tee.yml): simulated Confidential Space tokens,
# checked by the token verifier before key release (ADR 0004), the research
# lifecycle (publish, request, approve, query under disclosure control and a
# budget, revoke), and refusal of tampered tokens. Needs Docker, curl,
# openssl and jq.
#
# Not covered yet:
# - An approval retry after a revoke. On main it still restores access
#   (#166, fixed by #168); add the check once that merges.
# - Steward upload into a dataset: the API has none yet (P38). The steward's
#   data arrives through the sync pipeline, seeded at startup.
# - Ciphertext at rest: the vault is in memory inside the container, so this
#   script cannot read it from outside.
set -euo pipefail

COMPOSE_FILE="docker-compose.simulated-tee.yml"
# The demo tenant owns the sealed fixture, so it is also the steward.
TENANT_ID="6f2c8a2e-1111-4222-8333-444455556666"
RESEARCHER_ID="0b7d3c1e-2222-4333-8444-555566667777"
JWT_SECRET="simulated-tee-local-jwt-secret-32b!!"
# The fixture has two USD invoices and one EUR invoice, so with k = 2 a
# GROUP BY currency keeps one row and suppresses one.
MIN_COHORT=2

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

# api METHOD PATH TOKEN [BODY]: sets RESP_STATUS and RESP_BODY.
api() {
  local method="$1" path="$2" token="$3" body="${4:-}"
  local args=(-s -X "${method}" "http://127.0.0.1:8080${path}"
    -H "Authorization: Bearer ${token}" -w $'\n%{http_code}')
  if [[ -n "${body}" ]]; then
    args+=(-H "Content-Type: application/json" -d "${body}")
  fi
  local out
  out=$(curl "${args[@]}")
  RESP_STATUS="${out##*$'\n'}"
  RESP_BODY="${out%$'\n'*}"
}

# expect_response STEP STATUS [JQ_FILTER]: checks the last api call.
expect_response() {
  local step="$1" status="$2" filter="${3:-}"
  if [[ "${RESP_STATUS}" != "${status}" ]]; then
    echo "ERROR: ${step}: expected HTTP ${status}, got ${RESP_STATUS}: ${RESP_BODY}" >&2
    exit 1
  fi
  if [[ -n "${filter}" ]] && ! printf '%s' "${RESP_BODY}" | jq -e "${filter}" >/dev/null; then
    echo "ERROR: ${step}: response does not match ${filter}: ${RESP_BODY}" >&2
    exit 1
  fi
  echo "    ${step}: HTTP ${status}."
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

echo "==> [1/6] Building all images; starting sim-attestation and key-release-service..."
# Build every image now, so later stages never start one built from older code.
docker compose -f "${COMPOSE_FILE}" build
docker compose -f "${COMPOSE_FILE}" up -d sim-attestation key-release-service
wait_for_http "http://127.0.0.1:8070/healthz"
wait_for_http "http://127.0.0.1:8090/healthz"

echo "==> [2/6] Enrolling the demo tenant's key with key-release-service..."
PRIVATE_KEY_B64=$(openssl rand -base64 32)
ENROLL_JSON=$(curl -fsS -X PUT "http://127.0.0.1:8090/v1/keys" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"${TENANT_ID}\",\"private_key_b64\":\"${PRIVATE_KEY_B64}\"}")
TENANT_PUBKEY_B64=$(printf '%s' "${ENROLL_JSON}" | sed -n 's/.*"public_key_b64":"\([^"]*\)".*/\1/p')
if [[ -z "${TENANT_PUBKEY_B64}" ]]; then
  echo "ERROR: failed to extract public_key_b64 from key-release-service response: ${ENROLL_JSON}" >&2
  exit 1
fi

echo "==> [3/6] Starting enclave-api and sealing the synthetic QuickBooks fixture into its vault..."
DEMO_TENANT_ID="${TENANT_ID}" \
DEMO_TENANT_PUBLIC_KEY_B64="${TENANT_PUBKEY_B64}" \
RESEARCH_MIN_COHORT_SIZE="${MIN_COHORT}" \
  docker compose -f "${COMPOSE_FILE}" up -d enclave-api
wait_for_http "http://127.0.0.1:8080/healthz"

TOKEN=$(mint_jwt "${TENANT_ID}")

echo "==> [4/6] Verifying the attestation token and the confidential query happy path..."
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

echo "==> [5/6] Verifying the research lifecycle: publish, request, approve, query, revoke..."
RESEARCHER_TOKEN=$(mint_jwt "${RESEARCHER_ID}")
RESEARCH_QUERY="{\"steward_tenant\":\"${TENANT_ID}\",\"connector\":\"quickbooks\",\"sql\":\"SELECT currency, COUNT(*) AS n FROM quickbooks GROUP BY currency ORDER BY currency\"}"

api POST /api/v1/research/query "${RESEARCHER_TOKEN}" "${RESEARCH_QUERY}"
expect_response "query without a grant is refused" 403

api POST /api/v1/catalog "${TOKEN}" \
  '{"connector":"quickbooks","title":"Invoices","license_fee_cents":0,"compute_rate_cents":0}'
expect_response "steward publishes a listing" 200 '.listing_id | type == "string"'
LISTING_ID=$(printf '%s' "${RESP_BODY}" | jq -r .listing_id)

api POST "/api/v1/catalog/${LISTING_ID}/request" "${RESEARCHER_TOKEN}" '{}'
expect_response "researcher requests access" 200 '.status == "pending"'
REQUEST_ID=$(printf '%s' "${RESP_BODY}" | jq -r .request_id)

# A budget of 3 units: two queries and one refused probe use it up.
api POST "/api/v1/research/requests/${REQUEST_ID}/approve" "${TOKEN}" '{"query_budget":3}'
expect_response "steward approves with a 3-unit budget" 200 '.grant.revoked == false'
GRANT_ID=$(printf '%s' "${RESP_BODY}" | jq -r .grant.grant_id)

api POST /api/v1/research/query "${RESEARCHER_TOKEN}" "${RESEARCH_QUERY}"
expect_response "aggregate query keeps the USD cohort and suppresses EUR" 200 \
  '.rows == [{"currency":"USD","n":2}] and .suppressed_rows == 1
   and .budget_remaining == 2 and .tee_platform == "simulated"'

api POST /api/v1/research/query "${RESEARCHER_TOKEN}" \
  "{\"steward_tenant\":\"${TENANT_ID}\",\"connector\":\"quickbooks\",\"sql\":\"SELECT customer, total FROM quickbooks\"}"
expect_response "row-level query is refused" 422

api POST /api/v1/research/query "${RESEARCHER_TOKEN}" "${RESEARCH_QUERY}"
expect_response "the refused probe still cost a unit" 200 '.budget_remaining == 0'

api POST /api/v1/research/query "${RESEARCHER_TOKEN}" "${RESEARCH_QUERY}"
expect_response "query on a spent budget is refused" 429

api DELETE "/api/v1/grants/${GRANT_ID}" "${TOKEN}"
expect_response "steward revokes the grant" 200

api POST /api/v1/research/query "${RESEARCHER_TOKEN}" "${RESEARCH_QUERY}"
expect_response "query after the revoke is refused" 403

echo "==> [6/6] Verifying fail-closed refusal of tampered tokens..."
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
