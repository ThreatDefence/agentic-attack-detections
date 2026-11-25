#!/usr/bin/env bash
# Local Splunk + Elasticsearch/Kibana lab for the detections. See lab/README.md.
#
#   lab/lab.sh up [splunk|elastic]     start (both by default); first run writes lab/.env with new passwords
#   lab/lab.sh test [splunk|elastic]   load test events and rules, check every detection (leaves the data in place)
#   lab/lab.sh status                  containers, URLs and credentials
#   lab/lab.sh down                    stop, keep data
#   lab/lab.sh reset                   stop and delete all lab data
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$LAB")"
ENV="$LAB/.env"
PY="${PYTHON:-python3}"
compose() { docker compose --project-directory "$LAB" -f "$LAB/docker-compose.yml" --env-file "$ENV" "$@"; }

services() {
  case "${1:-all}" in
    splunk) echo splunk ;;
    elastic) echo elasticsearch kibana ;;
    all) echo splunk elasticsearch kibana ;;
    *) echo "unknown target $1 (splunk, elastic)" >&2; exit 2 ;;
  esac
}

write_env() {
  [ -f "$ENV" ] && return
  rnd() { "$PY" -c 'import secrets; print(secrets.token_hex(12))'; }
  umask 077
  cat > "$ENV" <<EOV
# Lab credentials, written by lab.sh. Not committed (.gitignore).
SPLUNK_PASSWORD=$(rnd)Aa1!
SPLUNK_HEC_TOKEN=$("$PY" -c 'import uuid; print(uuid.uuid4())')
ELASTIC_PASSWORD=$(rnd)
KIBANA_PASSWORD=$(rnd)
KIBANA_ENCRYPTION_KEY=$(rnd)$(rnd)
# SPLUNK_IMAGE=splunk/splunk:10.6.2
# ELASTIC_VERSION=9.5.5
EOV
  echo "wrote $ENV"
}

load_env() { set -a; . "$ENV"; set +a; }

package_splunk() {
  mkdir -p "$LAB/.build/splunk"
  "$PY" "$ROOT/tools/build_splunk.py" --package "$LAB/.build/splunk" >/dev/null
  COPYFILE_DISABLE=1 tar -C "$ROOT/tests/splunk" -czf "$LAB/.build/splunk/aad-test.tgz" TA-aad-test
  chmod -R a+rX "$LAB/.build"
}

wait_for() {  # name, seconds, command...
  local name=$1 secs=$2; shift 2
  printf 'waiting for %s' "$name"
  for _ in $(seq 1 $((secs / 5))); do
    if "$@" >/dev/null 2>&1; then echo " ready"; return; fi
    printf .; sleep 5
  done
  echo " gave up after ${secs}s"; return 1
}

up() {
  write_env; load_env
  local svc; svc=$(services "${1:-all}")
  [[ $svc == *splunk* ]] && package_splunk
  compose up -d $svc
  if [[ $svc == *elasticsearch* ]]; then
    wait_for Elasticsearch 300 curl -sf -u "elastic:$ELASTIC_PASSWORD" http://localhost:9200/_cluster/health
    curl -sf -u "elastic:$ELASTIC_PASSWORD" -H 'Content-Type: application/json' \
      -d "{\"password\":\"$KIBANA_PASSWORD\"}" http://localhost:9200/_security/user/kibana_system/_password >/dev/null
    wait_for Kibana 600 sh -c "curl -s -u 'elastic:$ELASTIC_PASSWORD' http://localhost:5601/api/status | grep -q '\"level\":\"available\"'"
  fi
  if [[ $svc == *splunk* ]]; then
    # Under emulation on Apple silicon the first start takes several minutes.
    wait_for Splunk 1200 sh -c "[ \"\$(docker inspect -f '{{.State.Health.Status}}' aad-splunk)\" = healthy ]"
  fi
  status
}

test_lab() {
  load_env
  local what=${1:-all} rc=0
  if [[ $what == all || $what == splunk ]]; then
    echo "== Splunk"; "$PY" "$ROOT/tests/splunk/run_tests.py" --url https://localhost:8089 --hec https://localhost:8088 || rc=1
  fi
  if [[ $what == all || $what == elastic ]]; then
    echo "== Elastic"; "$PY" "$ROOT/tests/elastic/run_tests.py" --keep-enabled "${@:2}" || rc=1
  fi
  return $rc
}

status() {
  load_env
  compose ps
  cat <<EOS

Splunk   http://localhost:8000   admin / $SPLUNK_PASSWORD   (HEC token $SPLUNK_HEC_TOKEN)
         test events: index=aad_test, app "Agentic Attack Detections"
Kibana   http://localhost:5601   elastic / $ELASTIC_PASSWORD
         test events: logs-aad.test-default, rules and alerts under Security > Rules / Alerts
EOS
}

cmd=${1:-}; shift || true
case "$cmd" in
  up) up "$@" ;;
  test) test_lab "$@" ;;
  status) status ;;
  down) compose down ;;
  reset) compose down -v; rm -rf "$LAB/.build" ;;
  *) sed -n '2,9p' "$0"; exit 2 ;;
esac
