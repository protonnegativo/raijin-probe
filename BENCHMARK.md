# Token benchmark: httpx vs raijin-probe

How many tokens does an AI agent spend reading the result of a probe, and does it lose anything? This benchmark probes a local lab with httpx, counts the tokens in each output shape, and checks that every httpx result is in the raijin-probe output.

Reproduce: `bench/run.sh` (set `HTTPX=<path>` if ProjectDiscovery httpx is not first on `PATH`).

## Setup

- **Lab:** `bench/lab.py`, one Python process serving small sites on `127.0.0.1`, ports 19200–19313. Each site is one kind: the nginx welcome page, the Apache default page, a 404, an admin login page, a 403, a 401 with Basic auth, a redirect to `/admin/login`, a redirect to https, a 500 from gunicorn, a Jenkins dashboard (Jetty, `X-Jenkins`), a Tomcat default page, a directory listing and a JSON API (Werkzeug). Each run also has one port with nothing listening.
- **httpx:** v1.6.10, defaults (no redirects followed).
- **raijin-probe:** runs httpx itself (`-json -silent -no-color -duc -probe -hash mmh3`) and saves its JSONL as `raw`. Defaults apply: no limit on findings, and `--max-bytes 16000`, which was not reached. The `--pretty` and `--format table` rows are separate live runs with the same result.
- **Baselines**, as an agent would run httpx:
  - `httpx -json -silent -duc`. It does not report the port with nothing listening, so it has one line less.
  - `httpx -json` with raijin-probe's flags: the `raw` file.
  - Text: `httpx -duc -nc -probe -sc -cl -ct -location -title -server -td`, stdout and stderr. It shows the same fields as the JSON and includes httpx's banner on stderr.
- **Tokens:** counted with tiktoken (`o200k_base`). This is a **proxy**, because Claude's tokenizer is not public. `bench/count_tokens.py` also gives exact Claude counts if `ANTHROPIC_API_KEY` is set and the `anthropic` package is installed. `cl100k_base` gives the same ratios.

## Scenario 1: noisy

56 targets: 40 nginx welcome pages, 8 Apache default pages, 4 identical 404s, 2 redirects to https, 1 Jenkins and 1 dead port. raijin-probe returned 1 finding (Jenkins: `panel`, `outlier`) and 5 groups.

| Output | Bytes | Tokens | vs. httpx -json |
|---|---:|---:|---:|
| httpx `-json` | 26,528 | 9,783 | 1× |
| httpx `-json` with raijin-probe's flags | 30,069 | 11,087 | 0.9× |
| httpx text (stdout+stderr) | 7,336 | 3,153 | 3.1× |
| **raijin-probe JSON (default)** | 2,536 | **1,104** | **8.9×** |
| raijin-probe `--pretty` | 3,638 | 1,409 | 6.9× |
| raijin-probe `--format table` | 430 | 148 | 66× |

## Scenario 2: interesting

15 targets, one of each kind (two identical 403s) and 1 dead port. raijin-probe returned 7 findings (admin login, directory listing, Jenkins and the redirect to `/admin/login` as medium; the two 403s, the 401 and the 500 as low) and 7 groups.

| Output | Bytes | Tokens | vs. httpx -json |
|---|---:|---:|---:|
| httpx `-json` | 6,570 | 2,411 | 1× |
| httpx `-json` with raijin-probe's flags | 7,668 | 2,825 | 0.85× |
| httpx text (stdout+stderr) | 1,949 | 823 | 2.9× |
| **raijin-probe JSON (default)** | 2,887 | **1,016** | **2.4×** |
| raijin-probe `--pretty` | 4,562 | 1,530 | 1.6× |
| raijin-probe `--format table` | 1,113 | 410 | 5.9× |

In both scenarios the raijin-probe JSON includes about 17 tokens for `raw`, the path of httpx's saved JSONL.

## Nothing is lost

For each scenario, `bench/verify.py` checks every httpx result (a line of the `raw` JSONL) against the raijin-probe output. A result is its URL (with the method when it is not GET), its redirect target and IPs, and what it answered: status, title, content length, webserver, tech, content type, CDN and error. The URL, written as raijin-probe writes a location, must be in the `locations` of a finding or group whose fields equal the result's fields.

- Scenario 1: 56 results, **0 missing**.
- Scenario 2: 15 results, **0 missing**.

What the JSON leaves out stays in httpx's JSONL, which raijin-probe saves to disk and points to in `raw`: timestamps, response times, word and line counts, hashes, ports, paths, schemes and httpx's `knowledgebase` guess.

## Reading the numbers

- **Against `httpx -json`**, the structured output an agent would parse, raijin-probe uses **8.9× fewer tokens** on the noisy run and **2.4× fewer** on the interesting run for the same URLs and fields. The gap grows with repetition: 40 identical nginx pages cost one set of fields plus 40 URLs.
- **Against httpx's text output**, the result depends on the run:
  - noisy: **2.9× smaller** (3,153 → 1,104);
  - interesting: **23% larger** (823 → 1,016).

  When every response is different there is nothing to collapse, and raijin-probe's JSON keys, IDs, tags and severities cost more than the text's brackets. In exchange the agent gets the dead port's error, field names it does not have to guess from position, and the panels and 403s ranked first.
- **The output stays bounded.** On a probe too big for `--max-bytes`, raijin-probe cuts the least important data first: group locations, then groups, then extra locations of low-ranked findings, then low-ranked findings. Every cut is counted in `omitted`, and `next` points to the raw file. Raw httpx output has no upper bound.

## How the default output got here

o200k tokens:

| Version | Scenario 1 | Scenario 2 | Lossless? |
|---|---:|---:|---|
| `type` written on every entry | 1,167 | 1,110 | yes |
| **`type` left out when `text/html`** (current) | **1,104** | **1,016** | **yes** |

Before the first benchmark run, two changes were made on a hand-run sample of the interesting lab: `->` in locations is no longer escaped as `\u003e`, and the outlier rule needs a baseline. The first outlier rule flagged every response seen once in a run of 10+ URLs, so the interesting run reported its nginx and Apache default pages as findings.
