#!/usr/bin/env bash
# End-to-end verification on the local Docker simulated TEE
# (docker-compose.simulated-tee.yml): simulated Confidential Space tokens,
# checked by the token verifier before key release (ADR 0004); a steward
# upload sealed as the browser seals it, and its refusals without a token,
# outside the upload namespace and at a stale version (ADR 0012); the
# research lifecycle on the upload (publish, request, approve, query under
# disclosure control and a budget, revoke, and an approval retry that does
# not undo the revoke); refusal of tampered tokens; and a vault that holds
# only the upload, its object and manifest sealed and its record in
# plaintext, both after the upload and after the queries. Needs Docker,
# curl, openssl and jq.
set -euo pipefail

COMPOSE_FILE="docker-compose.simulated-tee.yml"
# The steward: it enrolls its key, uploads the dataset and publishes it.
TENANT_ID="6f2c8a2e-1111-4222-8333-444455556666"
RESEARCHER_ID="0b7d3c1e-2222-4333-8444-555566667777"
JWT_SECRET="simulated-tee-local-jwt-secret-32b!!"
# The uploaded dataset: synth-data's cohort, whose groups are built around
# k. With k = 2, lupus has 1 row, celiac 2 and gout 3, so a research query
# over those three keeps celiac and gout and suppresses lupus.
DATASET="upload_cohort"
MIN_COHORT=2

cleanup() {
  local status=$?
  if [[ ${status} -ne 0 ]]; then
    docker compose -f "${COMPOSE_FILE}" logs --tail 20 >&2 || true
  fi
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans >/dev/null 2>&1 || true
  if [[ -n "${WORK_DIR:-}" ]]; then
    rm -rf "${WORK_DIR}"
  fi
}
trap cleanup EXIT

WORK_DIR=$(mktemp -d)
UPLOAD_BODY="${WORK_DIR}/upload.body"

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

QUERY="{\"connector\":\"${DATASET}\",\"sql\":\"SELECT condition, COUNT(*) AS n FROM ${DATASET} GROUP BY condition ORDER BY condition\"}"

query_status() {
  curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:8080/api/v1/query" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d "${QUERY}"
}

# api METHOD PATH TOKEN [BODY [CONTENT_TYPE]]: sets RESP_STATUS and
# RESP_BODY. An empty TOKEN sends no Authorization header. BODY is sent as
# it is (`@FILE` sends the file's bytes); CONTENT_TYPE defaults to JSON.
api() {
  local method="$1" path="$2" token="$3" body="${4:-}" type="${5:-application/json}"
  local args=(-s -X "${method}" "http://127.0.0.1:8080${path}" -w $'\n%{http_code}')
  if [[ -n "${token}" ]]; then
    args+=(-H "Authorization: Bearer ${token}")
  fi
  if [[ -n "${body}" ]]; then
    args+=(-H "Content-Type: ${type}" --data-binary "${body}")
  fi
  local out
  out=$(curl "${args[@]}")
  RESP_STATUS="${out##*$'\n'}"
  RESP_BODY="${out%$'\n'*}"
}

# upload TOKEN DATASET: PUTs the sealed upload body as DATASET.
upload() {
  api PUT "/api/v1/datasets/$2" "$1" "@${UPLOAD_BODY}" application/octet-stream
}

# research_query SQL: the body of a research query on the steward's dataset.
research_query() {
  jq -cn --arg steward "${TENANT_ID}" --arg connector "${DATASET}" --arg sql "$1" \
    '{steward_tenant: $steward, connector: $connector, sql: $sql}'
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

# check_vault NAME: copies enclave-api's vault (a directory in the
# enclave_vault volume, #153) to WORK_DIR/NAME and requires exactly what the
# upload stores (ADR 0012), at the version and object id the steward
# declared (DECLARED, the upload header): the object and the manifest as
# HPK1 envelopes, and the plaintext record. Any other file in the vault
# fails the check.
check_vault() {
  local vault="${WORK_DIR}/$1"
  local version object dataset stored expected envelope
  version=$(printf '%s' "${DECLARED}" | jq -r .version)
  object=$(printf '%s' "${DECLARED}" | jq -r .object)
  dataset="tenants/${TENANT_ID}/connectors/${DATASET}"
  local snapshot="${dataset}/snapshots/${version}/${object}.parquet"
  local manifest="${dataset}/manifests/${version}.manifest"
  local record="${dataset}/records/${version}.json"
  mkdir "${vault}"
  docker compose -f "${COMPOSE_FILE}" cp enclave-api:/var/lib/quackxide/vault/. "${vault}"
  stored=$(cd "${vault}" && find . ! -type d | sed 's|^\./||' | sort)
  expected=$(printf '%s\n' "${snapshot}" "${manifest}" "${record}" | sort)
  if [[ "${stored}" != "${expected}" ]]; then
    printf 'ERROR: the vault should hold exactly\n%s\nbut it holds\n%s\n' "${expected}" "${stored}" >&2
    exit 1
  fi
  # The record must hold its suite and what the steward declared, and nothing
  # else (`docs/THREAT_MODEL.md`, "Metadata").
  if ! jq -e --argjson declared "${DECLARED}" \
      '. == ($declared | {version, suite: "HPK1", row_cap, schema})' \
      "${vault}/${record}" >/dev/null 2>&1; then
    echo "ERROR: ${record} holds more or other than its suite and what the steward declared" >&2
    exit 1
  fi
  # An HPK1 envelope (platform-crypto's frame): the magic, a 32-byte
  # encapsulated key, then ciphertext ending in a 16-byte GCM tag.
  for envelope in "${snapshot}" "${manifest}"; do
    if ! cmp -s -n 4 <(printf 'HPK1') "${vault}/${envelope}" \
        || (( $(wc -c < "${vault}/${envelope}") < 52 )); then
      echo "ERROR: ${envelope} is not an HPK1 envelope" >&2
      exit 1
    fi
  done
  # The magic bytes that open and close every Parquet file, whatever its
  # compression. (A cell value would be found only while the Parquet is
  # uncompressed.)
  if grep -rlF -- "PAR1" "${vault}" >&2; then
    echo "ERROR: plaintext Parquet stored in the vault (files above)" >&2
    exit 1
  fi
}

echo "==> [1/9] Building all images; starting sim-attestation and key-release-service..."
# Build every image now, seal-upload's (profile "tools") included, so later
# stages never start one built from older code.
docker compose -f "${COMPOSE_FILE}" --profile tools build
docker compose -f "${COMPOSE_FILE}" up -d sim-attestation key-release-service
wait_for_http "http://127.0.0.1:8070/healthz"
wait_for_http "http://127.0.0.1:8090/healthz"

echo "==> [2/9] Enrolling the steward's key with key-release-service..."
PRIVATE_KEY_B64=$(openssl rand -base64 32)
ENROLL_JSON=$(curl -fsS -X PUT "http://127.0.0.1:8090/v1/keys" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"${TENANT_ID}\",\"private_key_b64\":\"${PRIVATE_KEY_B64}\"}")
TENANT_PUBKEY_B64=$(printf '%s' "${ENROLL_JSON}" | sed -n 's/.*"public_key_b64":"\([^"]*\)".*/\1/p')
if [[ -z "${TENANT_PUBKEY_B64}" ]]; then
  echo "ERROR: failed to extract public_key_b64 from key-release-service response: ${ENROLL_JSON}" >&2
  exit 1
fi

echo "==> [3/9] Starting enclave-api with an empty vault..."
RESEARCH_MIN_COHORT_SIZE="${MIN_COHORT}" \
  docker compose -f "${COMPOSE_FILE}" up -d enclave-api
wait_for_http "http://127.0.0.1:8080/healthz"

echo "==> [4/9] Uploading a synthetic cohort as the steward, sealed as the browser seals it..."
# seal-upload plays the steward's browser: it seals the Parquet and the
# snapshot manifest to the steward's public key, and declares the schema and
# row cap in the header (ADR 0012). It has no network and no private key;
# the body reaches the API from here.
docker compose -f "${COMPOSE_FILE}" run --rm -T seal-upload \
  --tenant "${TENANT_ID}" --public-key "${TENANT_PUBKEY_B64}" \
  --dataset "${DATASET}" --k "${MIN_COHORT}" > "${UPLOAD_BODY}"
TOKEN=$(mint_jwt "${TENANT_ID}")

upload "" "${DATASET}"
expect_response "upload without a token is refused" 401
upload "${TOKEN}" quickbooks
expect_response "upload outside the upload namespace is refused" 404
upload "${TOKEN}" "${DATASET}"
expect_response "steward uploads the dataset" 200 \
  ".dataset == \"${DATASET}\" and .suite == \"HPK1\""
upload "${TOKEN}" "${DATASET}"
expect_response "the same upload again is refused as a stale version" 409

echo "==> [5/9] Checking that the vault holds only the upload: two HPK1 envelopes and its record..."
# What the steward declared: the upload header, JSON after the 4-byte magic
# and its 4-byte big-endian length.
HEADER_LEN=$(od -An -tu1 -j4 -N4 "${UPLOAD_BODY}" \
  | awk '{ for (i = 1; i <= NF; i++) len = len * 256 + $i } END { print len + 0 }')
DECLARED=$(head -c "$((8 + HEADER_LEN))" "${UPLOAD_BODY}" | tail -c "${HEADER_LEN}")
check_vault after-upload
echo "    The vault holds the upload's object and manifest as HPK1 envelopes and its record, which holds only its suite and what the steward declared; nothing else, and no Parquet."

echo "==> [6/9] Verifying the attestation token and the confidential query happy path..."
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

echo "==> [7/9] Verifying the research lifecycle: publish, request, approve, query, revoke, retry..."
RESEARCHER_TOKEN=$(mint_jwt "${RESEARCHER_ID}")
RESEARCH_QUERY=$(research_query "SELECT condition, COUNT(*) AS n FROM ${DATASET} WHERE condition IN ('lupus', 'celiac', 'gout') GROUP BY condition ORDER BY condition")

api POST /api/v1/research/query "${RESEARCHER_TOKEN}" "${RESEARCH_QUERY}"
expect_response "query without a grant is refused" 403

api POST /api/v1/catalog "${TOKEN}" \
  "{\"connector\":\"${DATASET}\",\"title\":\"Synthetic cohort\",\"license_fee_cents\":0,\"compute_rate_cents\":0}"
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
expect_response "aggregate query keeps the celiac and gout cohorts and suppresses lupus" 200 \
  '.rows == [{"condition":"celiac","n":2},{"condition":"gout","n":3}]
   and .suppressed_rows == 1 and .budget_remaining == 2 and .tee_platform == "simulated"'

api POST /api/v1/research/query "${RESEARCHER_TOKEN}" \
  "$(research_query "SELECT person_id, condition FROM ${DATASET}")"
expect_response "row-level query is refused" 422

api POST /api/v1/research/query "${RESEARCHER_TOKEN}" "${RESEARCH_QUERY}"
expect_response "the refused probe still cost a unit" 200 '.budget_remaining == 0'

api POST /api/v1/research/query "${RESEARCHER_TOKEN}" "${RESEARCH_QUERY}"
expect_response "query on a spent budget is refused" 429

api DELETE "/api/v1/grants/${GRANT_ID}" "${TOKEN}"
expect_response "steward revokes the grant" 200

# Approving the request again is a retry: it finishes an approval that
# failed partway, but never undoes a revoke (#166).
api POST "/api/v1/research/requests/${REQUEST_ID}/approve" "${TOKEN}" '{"query_budget":3}'
expect_response "an approval retry after the revoke is refused" 404

api POST /api/v1/research/query "${RESEARCHER_TOKEN}" "${RESEARCH_QUERY}"
expect_response "query after the revoke and the retry is refused" 403

echo "==> [8/9] Verifying fail-closed refusal of tampered tokens..."
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

echo "==> [9/9] Checking the vault again after the queries..."
check_vault after-queries
echo "    The vault still holds only the upload's two HPK1 envelopes and its record."

echo "==> All simulated TEE Docker verification checks passed."
