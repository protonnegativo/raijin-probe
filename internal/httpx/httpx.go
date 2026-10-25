// Package httpx runs the ProjectDiscovery httpx binary and parses its JSONL output.
package httpx

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// ErrNotFound is returned when the httpx binary is not on PATH.
var ErrNotFound = errors.New("httpx binary not found")

// Event is the subset of an httpx JSONL result that Raijin uses.
type Event struct {
	URL           string         `json:"url"`
	Input         string         `json:"input"`
	Method        string         `json:"method"`
	StatusCode    int            `json:"status_code"`
	Title         string         `json:"title"`
	ContentLength int            `json:"content_length"`
	ContentType   string         `json:"content_type"`
	Webserver     string         `json:"webserver"`
	Tech          []string       `json:"tech"`
	Location      string         `json:"location"`
	FinalURL      string         `json:"final_url"`
	Words         int            `json:"words"`
	Lines         int            `json:"lines"`
	A             []string       `json:"a"`
	CDN           bool           `json:"cdn"`
	CDNName       string         `json:"cdn_name"`
	Hash          map[string]any `json:"hash"`
	Failed        bool           `json:"failed"`
	Error         string         `json:"error"`
}

// BodyHash returns the body hash httpx computed (-hash), or "" if there is none. httpx writes it as a
// string, but any JSON value is accepted so an odd value never drops the event.
func (e Event) BodyHash() string {
	for _, k := range []string{"body_mmh3", "body_sha256", "body_md5", "body_sha1", "body_simhash", "body_sha512"} {
		if v, ok := e.Hash[k]; ok && v != nil {
			return k + ":" + fmt.Sprint(v)
		}
	}
	return ""
}

// Options are the httpx settings Raijin passes through.
type Options struct {
	Binary  string
	Rate    int
	Timeout int
	Threads int
	// Follow follows redirects on the same host (httpx -fhr), so a probe never leaves the host it was given.
	Follow bool
	Extra  []string
	// RawPath, if set, receives httpx's JSONL output unchanged.
	RawPath string
}

// Version runs httpx -version and returns what it printed, or "" if it did not answer within 3 seconds.
// httpx writes its banner and "Current Version: vX.Y.Z" to stderr.
func Version(ctx context.Context, bin string) string {
	if bin == "" {
		bin = "httpx"
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, bin, "-version", "-duc").CombinedOutput()
	if ctx.Err() != nil {
		return ""
	}
	return string(out)
}

// Run probes the targets and returns every event, the number of output lines that were not httpx
// results, and the last stderr lines if httpx failed.
func Run(ctx context.Context, targets []string, opt Options) ([]Event, int, string, error) {
	bin := opt.Binary
	if bin == "" {
		bin = "httpx"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, 0, "", ErrNotFound
	}

	list, err := os.CreateTemp("", "raijin-probe-targets-*.txt")
	if err != nil {
		return nil, 0, "", err
	}
	defer os.Remove(list.Name())
	if _, err := io.WriteString(list, strings.Join(targets, "\n")+"\n"); err != nil {
		list.Close()
		return nil, 0, "", err
	}
	list.Close()

	cmd := exec.CommandContext(ctx, path, Args(list.Name(), opt)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, 0, "", err
	}
	var r io.Reader = stdout
	if opt.RawPath != "" {
		raw, err := os.Create(opt.RawPath)
		if err != nil {
			return nil, 0, "", err
		}
		defer raw.Close()
		r = io.TeeReader(stdout, raw)
	}
	if err := cmd.Start(); err != nil {
		return nil, 0, "", err
	}
	events, unparsed, parseErr := Parse(r)
	waitErr := cmd.Wait()
	if parseErr != nil {
		return events, unparsed, tail(stderr.String(), 3), parseErr
	}
	if waitErr != nil {
		return events, unparsed, tail(stderr.String(), 3), fmt.Errorf("httpx exited: %w", waitErr)
	}
	return events, unparsed, "", nil
}

// Args builds the httpx command line. -probe reports targets that did not answer, and -hash mmh3 gives
// the body hash that tells identical responses apart.
func Args(listFile string, opt Options) []string {
	args := []string{"-l", listFile, "-json", "-silent", "-no-color", "-duc", "-probe", "-hash", "mmh3"}
	if opt.Follow {
		args = append(args, "-fhr")
	}
	if opt.Rate > 0 {
		args = append(args, "-rl", fmt.Sprint(opt.Rate))
	}
	if opt.Timeout > 0 {
		args = append(args, "-timeout", fmt.Sprint(opt.Timeout))
	}
	if opt.Threads > 0 {
		args = append(args, "-t", fmt.Sprint(opt.Threads))
	}
	return append(args, opt.Extra...)
}

// Parse reads httpx JSONL. httpx log lines ("[INF] ...", written when -silent is off) are skipped; other
// lines that are not JSON objects with a URL are skipped and counted.
func Parse(r io.Reader) ([]Event, int, error) {
	var events []Event
	unparsed := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || logLine.Match(line) {
			continue
		}
		var ev Event
		if line[0] != '{' || json.Unmarshal(line, &ev) != nil {
			unparsed++
			continue
		}
		if ev.URL == "" {
			ev.URL = ev.Input
		}
		if ev.URL == "" {
			unparsed++
			continue
		}
		events = append(events, ev)
	}
	return events, unparsed, sc.Err()
}

// FormatHint says when httpx's output does not look like what the reducer reads: every result needs a
// url and either status_code or failed. unparsed counts the lines that were not results at all. It
// returns "" when the output looks right.
func FormatHint(events []Event, unparsed int, raw string) string {
	bad := unparsed
	for _, ev := range events {
		if ev.StatusCode == 0 && !ev.Failed {
			bad++
		}
	}
	if bad == 0 {
		return ""
	}
	hint := fmt.Sprintf("%d of %d httpx results had no url and status_code or failed; the engine's output format may have changed", bad, len(events)+unparsed)
	if raw != "" {
		hint += ". Read " + raw + " for the full output"
	}
	return hint
}

var logLine = regexp.MustCompile(`^\[(INF|WRN|ERR|FTL|DBG|VER)\] `)

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
