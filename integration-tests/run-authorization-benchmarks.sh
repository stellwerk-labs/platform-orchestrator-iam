#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

duration="${DURATION:-60s}"
vus_matrix="${VUS_MATRIX:-1 10 50 100 250}"
datasets="${DATASETS:-hot projects}"
permissions="${PERMISSIONS:-read deployment_cancel}"
checks_per_request_matrix="${CHECKS_PER_REQUEST_MATRIX:-1}"
developer_count="${DEVELOPER_COUNT:-5000}"
developers_per_org="${DEVELOPERS_PER_ORG:-50}"
projects_per_developer="${PROJECTS_PER_DEVELOPER:-5}"
invalidation_interval="${INVALIDATION_INTERVAL:-}"
results_dir="${RESULTS_DIR:-$(mktemp -d)}"

if [[ ! -f compose.yaml ]]; then
  echo "compose.yaml is missing; run 'make build' first" >&2
  exit 1
fi

mkdir -p "$results_dir"

postgres_service="$(docker compose config --services | awk '/^pg-/ && !/-init$/ { print; exit }')"
database_name="$(score-compose resources get-outputs 'postgres.default#platform-orchestrator-iam.postgres' | jq -r .name)"
compose_project="$(docker compose config --format json | jq -r .name)"
docker_network="${compose_project}_default"
iam_service="platform-orchestrator-iam-platform-orchestrator-iam"
target="http://${iam_service}:8080"
nats_url="nats://nats:4222"
policy_invalidation_subject="platform-orchestrator-iam.authorization.policy.invalidate"

docker compose exec -T "$postgres_service" psql -U postgres -d "$database_name" \
  -v ON_ERROR_STOP=1 \
  -v developer_count="$developer_count" \
  -v developers_per_org="$developers_per_org" \
  -v projects_per_developer="$projects_per_developer" \
  < authorization-benchmark-seed.sql

docker compose restart "$iam_service" >/dev/null
until curl -fsS http://localhost:8081/health >/dev/null; do
  sleep 1
done

hot_user="10000000-0000-4000-8000-000000000001"
hot_resource="organization:authorization-benchmark-org-0001"

invalidation_container=""
cleanup() {
  if [[ -n "$invalidation_container" ]]; then
    docker rm -f "$invalidation_container" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ -n "$invalidation_interval" ]]; then
  invalidation_container="stellwerk-authorization-invalidator-$$"
  docker run --rm -d \
    --name "$invalidation_container" \
    --network "$docker_network" \
    natsio/nats-box:0.19.5 sh -c \
    "while true; do nats pub --server '$nats_url' '$policy_invalidation_subject' benchmark; sleep '$invalidation_interval'; done" >/dev/null
fi

echo -e "dataset\tpermission\tchecks\tvus\treq/s\tavg_ms\tp95_ms\tp99_ms\tmax_ms\tfailure_rate\trequests"
for dataset in $datasets; do
  for permission in $permissions; do
    for checks_per_request in $checks_per_request_matrix; do
      for vus in $vus_matrix; do
        name="${dataset}-${permission}-${checks_per_request}checks-${vus}vus"
        docker run --rm \
          --network "$docker_network" \
          -v "$script_dir/authorization-throughput.js:/script.js:ro" \
          -v "$results_dir:/results" \
          -e TARGET="$target" \
          -e DATASET="$dataset" \
          -e DURATION="$duration" \
          -e VUS="$vus" \
          -e USER_ID="$hot_user" \
          -e RESOURCE="$hot_resource" \
          -e PERMISSION="$permission" \
          -e CHECKS_PER_REQUEST="$checks_per_request" \
          -e DEVELOPER_COUNT="$developer_count" \
          -e DEVELOPERS_PER_ORG="$developers_per_org" \
          -e PROJECTS_PER_DEVELOPER="$projects_per_developer" \
          grafana/k6:latest run --quiet --summary-export "/results/${name}.json" /script.js >/dev/null

        jq -r --arg dataset "$dataset" --arg permission "$permission" --arg checks "$checks_per_request" --arg vus "$vus" '
          [$dataset, $permission, $checks, $vus,
           (.metrics.http_reqs.rate | tostring),
           (.metrics.http_req_duration.avg | tostring),
           (.metrics.http_req_duration["p(95)"] | tostring),
           (.metrics.http_req_duration["p(99)"] | tostring),
           (.metrics.http_req_duration.max | tostring),
           (.metrics.http_req_failed.value | tostring),
           (.metrics.http_reqs.count | tostring)] | @tsv
        ' "$results_dir/${name}.json"
      done
    done
  done
done

echo "Detailed k6 summaries: $results_dir" >&2
