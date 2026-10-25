#!/usr/bin/env bash
# Reproducible token benchmark: httpx output vs raijin-probe output on the same local lab.
#
# usage: bench/run.sh [workdir]          replay the httpx output saved in bench/fixtures
#        LIVE=1 bench/run.sh [workdir]   start the local lab, probe it and refresh bench/fixtures first
# needs: python3 with tiktoken (pip install tiktoken), go; LIVE=1 also needs httpx (ProjectDiscovery)
# optional: ANTHROPIC_API_KEY + pip install anthropic for exact Claude token counts
# env: HTTPX=<path> to pick the httpx binary, PY=<python with tiktoken>
set -euo pipefail

W=${1:-$(mktemp -d)}
HERE=$(cd "$(dirname "$0")" && pwd)
HTTPX=${HTTPX:-httpx}
PY=${PY:-python3}
mkdir -p "$W"
echo "workdir: $W"

ROOT=$(cd "$HERE/.." && pwd)
(cd "$ROOT" && go build -o "$W/raijin-probe" ./cmd/raijin-probe)
printf '127.0.0.1\n' > "$W/scope.txt"

# Lab: one python process serving many small sites on 127.0.0.1 (see lab.py for the kinds).
# noisy: 40 identical nginx welcome pages, 8 Apache default pages, 4 identical 404s, 2 redirects to
#        https, 1 Jenkins and 1 port with nothing listening.
# interesting: one of each kind (two identical 403s) and 1 port with nothing listening.
if [ "${LIVE:-}" = 1 ]; then
  noisy=(); interesting=()
  p=19200
  for k in $(printf 'nginx %.0s' {1..40}) $(printf 'apache %.0s' {1..8}) notfound notfound notfound notfound tohttps tohttps jenkins; do
    noisy+=("$p=$k"); p=$((p+1))
  done
  p=19300
  for k in nginx apache notfound login forbidden forbidden basic tologin tohttps error jenkins tomcat listing api; do
    interesting+=("$p=$k"); p=$((p+1))
  done
  for spec in "${noisy[@]}" "${interesting[@]}" 19299=dead 19399=dead; do
    port=${spec%%=*}
    if ss -ltn | grep -q ":$port "; then echo "port $port is busy; free it first" >&2; exit 1; fi
  done
  python3 "$HERE/lab.py" "${noisy[@]}" "${interesting[@]}" > "$W/lab.log" 2>&1 &
  echo $! > "$W/pids"
  trap '[ -f "$W/pids" ] && xargs kill < "$W/pids" 2>/dev/null || true' EXIT
  sleep 1

  targets() { for spec in "$@"; do echo "http://127.0.0.1:${spec%%=*}"; done; }
  targets "${noisy[@]}" 19299=dead > "$W/noisy.txt"
  targets "${interesting[@]}" 19399=dead > "$W/interesting.txt"
  for name in noisy interesting; do
    f=$HERE/fixtures/$name
    mkdir -p "$f"
    cp "$W/$name.txt" "$f/targets.txt"
    # httpx as an agent would run it: plain JSON, and text with the same fields shown.
    "$HTTPX" -l "$f/targets.txt" -json -silent -duc < /dev/null > "$f/httpx.jsonl"
    "$HTTPX" -l "$f/targets.txt" -duc -nc -probe -sc -cl -ct -location -title -server -td < /dev/null > "$f/text.txt" 2> "$f/text_stderr.txt"
    # raijin-probe runs httpx itself (-json -silent -duc -probe -hash mmh3) and saves its JSONL as raw:
    # that file is the fixture the other rows replay.
    "$W/raijin-probe" --httpx "$HTTPX" --scope "$W/scope.txt" -l "$f/targets.txt" --raw "$f/raw.jsonl" > "$W/$name.live.json"
  done
  cp -r "$HERE/fixtures" "$W/fixtures"
fi

scenario() {
  local name=$1
  local f=$HERE/fixtures/$name o=$W/$name
  mkdir -p "$o"
  # raijin-probe replays raw with --input, so every row sees the same httpx results.
  (cd "$ROOT" && "$W/raijin-probe" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.jsonl") > "$o/raijin.json"
  (cd "$ROOT" && "$W/raijin-probe" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.jsonl" --pretty) > "$o/raijin_pretty.json"
  (cd "$ROOT" && "$W/raijin-probe" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.jsonl" --format table) > "$o/raijin_table.txt"
  echo; echo "## $name ($(wc -l < "$f/raw.jsonl") httpx results)"; echo
  python3 "$HERE/verify.py" "$f/raw.jsonl" "$o/raijin.json"
  "$PY" "$HERE/count_tokens.py" \
    "httpx -json (raijin-probe's flags)=$f/raw.jsonl" \
    "httpx -json=$f/httpx.jsonl" \
    "httpx text (stdout+stderr)=$f/text.txt+$f/text_stderr.txt" \
    "raijin-probe JSON (default)=$o/raijin.json" \
    "raijin-probe --pretty=$o/raijin_pretty.json" \
    "raijin-probe --format table=$o/raijin_table.txt"
}

scenario noisy
scenario interesting
