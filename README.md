# ⚡ Raijin Probe

[![CI](https://github.com/protonnegativo/raijin-probe/actions/workflows/ci.yml/badge.svg)](https://github.com/protonnegativo/raijin-probe/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/protonnegativo/raijin-probe)](https://github.com/protonnegativo/raijin-probe/releases/latest)
[![License: MIT](https://img.shields.io/github/license/protonnegativo/raijin-probe)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/protonnegativo/raijin-probe.svg)](https://pkg.go.dev/github.com/protonnegativo/raijin-probe)
[![Go Report Card](https://goreportcard.com/badge/github.com/protonnegativo/raijin-probe)](https://goreportcard.com/report/github.com/protonnegativo/raijin-probe)

**httpx for AI agents: every URL with its status, title, tech and size, identical responses collapsed, the interesting hosts ranked first.**

`raijin-probe` is a tool of **Raijin**, an arsenal of offensive security tools built for AI agents. It runs [httpx](https://github.com/projectdiscovery/httpx) underneath and returns the **Raijin Schema**: one compact JSON where URLs that returned the same response share one entry, login panels, directory listings, 401/403s, 5xx errors and outliers are ranked findings, and anything it had to cut is counted.

## Why not just run httpx?

httpx is built for people and pipelines. An agent pays for every byte it reads. Its JSON output is one line per URL, and every line repeats the timestamp, the input, the scheme, the port, the path, the IPs, the hashes and the field names, even when 40 hosts serve the same nginx welcome page. The text output is shorter but has no structure and no ranking.

Here is the same probe, with the same URLs, read by an agent (tokens, `o200k_base`):

```
Noisy run: 56 URLs, 40 identical nginx pages, 1 Jenkins
  raijin-probe    ██▎                      1,104 tokens
  httpx text      ██████▌                  3,153 tokens
  httpx -json     ████████████████████     9,783 tokens

Interesting run: 15 URLs, all different
  raijin-probe    ████████▌                1,016 tokens
  httpx text      ██████▉                    823 tokens
  httpx -json     ████████████████████     2,411 tokens
```

raijin-probe reads **8.9×** fewer tokens than `httpx -json` on the noisy run and **2.4×** fewer on the interesting run. Each run's bars are drawn to scale against `httpx -json`.

- **Nothing is lost.** Every URL httpx probed is in the output, with its status, title, length, server, tech, content type, redirect target and IPs. `bench/verify.py` checked all 71 httpx results in both runs and none were missing.
- **The real targets come first.** A login panel, a Jenkins dashboard, a directory listing and a 403 are findings, ranked by severity. 40 identical default pages are one group that lists all 40 URLs.
- **Output is bounded.** On a huge probe, `--max-bytes` cuts the least important data first and counts every cut. httpx's output grows with every URL.
- **Details are one file away.** httpx's full JSONL is saved to disk, and its path is in `raw`. It holds the timestamps, response times, word and line counts, hashes and everything else, and it costs no tokens until the agent opens it.

Against httpx's text output (with `-sc -cl -ct -location -title -server -td`), raijin-probe is **2.9×** smaller on the noisy run and **23% larger** on the interesting run. When every response is different there is nothing to collapse, and the JSON keys, IDs, tags and severities cost more than the text's brackets. The text output also has no dedup, no ranking and no field names. Full method and numbers are in [BENCHMARK.md](BENCHMARK.md), and `bench/run.sh` reproduces them.

## Install

```bash
go install github.com/protonnegativo/raijin-probe/cmd/raijin-probe@latest
```

This installs the latest release.

You also need ProjectDiscovery `httpx` on `PATH`, or pass `--httpx <path>`. The Python `httpx` CLI is a different tool and will not work.

### Versions

Releases are tagged automatically on every change and every passing engine update. `raijin-probe --version` shows the release and the tested engine versions, e.g. `raijin-probe v0.1.3 (tested with httpx 1.12.0)`. `raijin-mcp update` updates every Raijin tool at once.

## Usage

```bash
raijin-probe --scope scope.txt                                # probe every host the scope names
raijin-probe --scope scope.txt -l hosts.txt
raijin-probe --scope scope.txt -u app.example.com -u api.example.com
raijin-probe --scope scope.txt --input httpx-results.jsonl    # reduce output you already have
raijin-probe --scope scope.txt -l hosts.txt --state run.json  # mark findings that are new since last run
raijin-probe --scope scope.txt -l hosts.txt --follow          # follow redirects on the same host
raijin-probe ... -- -p 80,443,8080,8443 -path /admin          # anything after -- goes to httpx
```

`--scope` is required. One rule per line:

```
example.com
*.example.com
10.0.0.0/24
!admin.example.com
```

With no `-u`, `-l` or `--input`, raijin-probe probes what the scope names: every domain, every IP, and every address of ranges up to a /24, minus exclusions. A wildcard names no host and a larger range is too big to sweep blindly, so for each one `next` gives the command that enumerates it first (`raijin-subs` or `raijin-ports`).

Targets outside the scope are dropped before httpx runs, and results for out-of-scope URLs are dropped from the output. Both are counted in `omitted.out_of_scope`.

## Output

```json
{
  "schema_version": 1,
  "tool": "raijin-probe",
  "version": "v0.1.0",
  "target": "56 target(s)",
  "summary": "56 URLs, 1 findings (1 medium), 5 groups, 1 no response",
  "findings": [
    {
      "id": "200-fe9737d0",
      "title": "Dashboard [Jenkins]",
      "severity": "medium",
      "tags": ["panel", "outlier"],
      "status": 200,
      "length": 238,
      "server": "Jetty(10.0.13)",
      "tech": ["Java", "Jenkins:2.401.3", "Jetty:10.0.13"],
      "locations": ["http://127.0.0.1:19254"]
    }
  ],
  "groups": [
    {
      "id": "200-066db89a",
      "title": "Welcome to nginx!",
      "status": 200,
      "length": 615,
      "server": "nginx/1.18.0 (Ubuntu)",
      "tech": ["Nginx:1.18.0", "Ubuntu"],
      "locations": ["http://127.0.0.1:19200", "http://127.0.0.1:19201", "http://127.0.0.1:19202", "... 37 more"]
    },
    {
      "id": "404-8367bd08",
      "title": "404 Not Found",
      "status": 404,
      "length": 133,
      "server": "nginx",
      "tech": ["Nginx"],
      "locations": ["http://127.0.0.1:19248", "http://127.0.0.1:19249", "http://127.0.0.1:19250", "http://127.0.0.1:19251"]
    },
    {
      "id": "301-00720d3b",
      "title": "301 Moved Permanently",
      "status": 301,
      "length": 79,
      "server": "nginx",
      "tech": ["Nginx"],
      "locations": ["http://127.0.0.1:19252 -> https://127.0.0.1/", "http://127.0.0.1:19253 -> https://127.0.0.1/"]
    },
    {
      "id": "failed-980ccf07",
      "error": "chain=\"connection refused\"",
      "locations": ["http://127.0.0.1:19299"]
    }
  ],
  "raw": "/tmp/raijin-probe-180340019.jsonl"
}
```

That is the real noisy run from the benchmark, pretty-printed here. Two things are shortened: the nginx group lists all 40 URLs in the real output (37 are replaced by `"... 37 more"` here), and the group of 8 Apache default pages is left out. The tool writes it as one line.

**Nothing httpx found is dropped silently.** Every URL is in exactly one finding or group. Only exact repeats collapse, and they are counted in `omitted.duplicates`.

What the reducer does:

- **One entry per distinct response.** Two URLs returned the same response when the status, title, content length, word and line counts, server, tech, content type, CDN, error and body hash (`-hash mmh3`) are all equal. Each entry lists every URL that returned it.
- **Each location is one URL**, written as `[METHOD ]url[ -> redirect][ [ip, ...]]`. The method is written when it is not GET. The redirect is httpx's `final_url` when it followed the redirect, and the `Location` header otherwise. The IPs are written when the URL host is a name. The same URL with a different response is two locations in two entries, not a duplicate.
- **Findings** are the responses that match a rule. Each rule has a fixed severity, and a finding takes the highest:

  | Tag | Severity | Rule |
  |---|---|---|
  | `panel` | medium | The title, URL path or redirect target says login, sign in, admin, dashboard, console, portal, manager, phpMyAdmin, wp-admin and similar, or httpx detected panel tech (Jenkins, Grafana, Kibana, GitLab, Portainer, Argo CD and others). |
  | `listing` | medium | The title is a directory index (`Index of /`, `Directory listing for`). |
  | `auth` | low | Status 401, 403 or 407. |
  | `error` | low | Status 5xx. |
  | `outlier` | low, `heuristic` | Only one URL returned it, in a run of at least 10 answering URLs where one response covers at least half of them. A run with no such baseline has no outliers. |

  An `outlier` with no other tag has `confidence: heuristic`.
- **Groups** are the responses that match no rule: default pages, 200s, 404s, redirects that go nowhere special, and probes that failed (status left out, `error` set).
- **Ranking:** findings by severity, then confidence (matched before heuristic), then the number of URLs, then `id`. Groups by the number of URLs, then `id`. The same input always gives the same order.
- **`id`** is the status (or `failed`) and a short hash of the response, so the same response has the same `id` in the next run.
- **`raw`** is httpx's full JSONL, saved to disk. It holds the timestamps, response times, word and line counts, hashes, ports, paths and schemes. Reading it costs no tokens until the agent opens it. `--raw <file>` picks the path.
- **Budget:** `--max-bytes` (16,000 by default) keeps the output bounded on huge probes. It cuts in this order until the JSON fits:
  1. group locations;
  2. groups;
  3. the locations of the lowest-ranked findings, each keeping one location plus its `count`;
  4. the lowest-ranked findings.

  Every cut is counted in `omitted`, `budget.truncated` is set, and `next` points to the raw file. `--max-items` caps the number of findings (0, the default, keeps all).
- **Errors** say what to try next. If httpx is missing, the exit code is 2.
- **`schema_version`** (currently 1) is the first field of every result and changes only when the schema breaks.
- **An invalid scope file** runs nothing and returns one error per bad line, each with `kind: "scope"` and the line number in `hint` (for example `line 2: port in rule`).
- **Exit codes:** 0 ok; 1 wrong usage (bad flag, missing `--scope`, no target in scope); 2 structured error, with the JSON result on stdout (invalid scope, httpx missing). An agent tells them apart by `errors[].kind`.

Fields an agent can rebuild are left out to save tokens:

- `type` (the content type) is left out when it is `text/html`, and is `none` when the server sent none.
- `title`, `length`, `server`, `tech` and `cdn` are left out when httpx had none (length 0).
- `status` is left out when the probe failed; `error` says why.
- `count` appears only when the budget cut `locations`.
- `confidence` appears only when it is not `matched`.
- `omitted`, `errors` and `next` appear only when they are not empty.
- `budget` appears only when something was cut.

The JSON is compact (one line) by default because indentation costs 28% to 51% more tokens in the benchmark; `--pretty` indents it (the example above is pretty-printed). `--format table` prints a short human view of the same result; it lists finding URLs but only counts group URLs.

The Raijin banner is **off by default**, so normal runs stay small. `--banner` prints it to **stderr** (never stdout, so the JSON is untouched), with the version taken from the binary. Colors are disabled when `NO_COLOR` is set or stderr is not a terminal.

## Flags

| Flag | Default | |
|---|---|---|
| `--scope` | (required) | scope file |
| `-u` / `-l` / `--input` | every host the scope names | one target (repeatable) / target file / existing httpx JSONL |
| `--rate`, `--timeout`, `--threads` | | httpx `-rl` / `-timeout` / `-t` |
| `--follow` | false | follow redirects on the same host (httpx `-fhr`) |
| `--max-items` | 0 | max findings (0 keeps all) |
| `--max-bytes` | 16000 | max JSON size; cuts are counted in `omitted` |
| `--raw` | temp file | where to save httpx's full JSONL |
| `--state` | | state file for new-since-last-run |
| `--format` | json | `json` or `table` |
| `--pretty` | false | indent the JSON |
| `--httpx` | httpx | path to the binary |
| `--banner` | false | print the banner to stderr |

## Engine versions

raijin-probe is tested with the httpx version in [engines.json](engines.json), which is built into the binary. Before a run it checks `httpx -version`: another major version, or an older one, adds an `engine_version` error with the command to install the tested version. If httpx's output does not have the fields raijin-probe reads (`url` and `status_code` or `failed`), it adds an `engine_format` error. Neither changes the exit code. A weekly job tests the latest httpx against the benchmark lab and commits the bump and tags a release when it passes, or an issue when it breaks.

## Development

```bash
go test ./...
go vet ./...
```

The only dependency is [raijin-core](https://github.com/protonnegativo/raijin-core) (scope, state, result envelope); the rest is the standard library. httpx runs as a subprocess with `-json -silent -no-color -duc -probe -hash mmh3`, so the binary stays small and httpx can be updated on its own. `-probe` makes httpx report the targets that did not answer, and the body hash tells identical responses apart.

## Responsible use

Only probe what you are authorized to test.
