#!/usr/bin/env bash
# Reproducible token benchmark: httpx output vs raijin-probe output on the same local lab.
#
# usage: bench/run.sh [workdir]
# needs: httpx (ProjectDiscovery), python3 with tiktoken (pip install tiktoken), go
# optional: ANTHROPIC_API_KEY + pip install anthropic for exact Claude token counts
# env: HTTPX=<path> to pick the httpx binary, PY=<python with tiktoken>
set -euo pipefail

W=${1:-$(mktemp -d)}
HERE=$(cd "$(dirname "$0")" && pwd)
HTTPX=${HTTPX:-httpx}
PY=${PY:-python3}
mkdir -p "$W"
echo "workdir: $W"

# Lab: one python process serving many small sites on 127.0.0.1 (see lab.py for the kinds).
# noisy: 40 identical nginx welcome pages, 8 Apache default pages, 4 identical 404s, 2 redirects to
#        https, 1 Jenkins and 1 port with nothing listening.
# interesting: one of each kind (two identical 403s) and 1 port with nothing listening.
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
printf '127.0.0.1\n' > "$W/scope.txt"

(cd "$HERE/.." && go build -o "$W/raijin-probe" ./cmd/raijin-probe)

scenario() {
  local name=$1
  local o=$W/$name
  mkdir -p "$o"
  # httpx as an agent would run it: plain JSON, and text with the same fields shown.
  "$HTTPX" -l "$W/$name.txt" -json -silent -duc < /dev/null > "$o/httpx.jsonl"
  "$HTTPX" -l "$W/$name.txt" -duc -nc -probe -sc -cl -ct -location -title -server -td < /dev/null > "$o/text.txt" 2> "$o/text_stderr.txt"
  # raijin-probe runs httpx itself (-json -silent -duc -probe -hash mmh3) and saves its JSONL as raw.
  # The raw file keeps its default temp path, as in a normal run, and is copied next to the outputs.
  "$W/raijin-probe" --httpx "$HTTPX" --scope "$W/scope.txt" -l "$W/$name.txt" > "$o/raijin.json"
  mv "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["raw"])' "$o/raijin.json")" "$o/raw.jsonl"
  # The other shapes are live runs too, so every raijin-probe row carries the same target and raw lines.
  "$W/raijin-probe" --httpx "$HTTPX" --scope "$W/scope.txt" -l "$W/$name.txt" --pretty > "$o/raijin_pretty.json"
  rm -f "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["raw"])' "$o/raijin_pretty.json")"
  "$W/raijin-probe" --httpx "$HTTPX" --scope "$W/scope.txt" -l "$W/$name.txt" --format table --raw "$o/raw_table.jsonl" > "$o/raijin_table.txt"
  echo; echo "## $name ($(wc -l < "$o/raw.jsonl") httpx results)"; echo
  python3 "$HERE/verify.py" "$o/raw.jsonl" "$o/raijin.json"
  "$PY" "$HERE/count_tokens.py" \
    "httpx -json (raijin-probe's flags)=$o/raw.jsonl" \
    "httpx -json=$o/httpx.jsonl" \
    "httpx text (stdout+stderr)=$o/text.txt+$o/text_stderr.txt" \
    "raijin-probe JSON (default)=$o/raijin.json" \
    "raijin-probe --pretty=$o/raijin_pretty.json" \
    "raijin-probe --format table=$o/raijin_table.txt"
}

scenario noisy
scenario interesting
