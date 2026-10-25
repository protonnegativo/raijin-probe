package httpx

import (
	"strings"
	"testing"
)

func TestArgs(t *testing.T) {
	got := strings.Join(Args("list.txt", Options{Follow: true, Rate: 10, Timeout: 5, Threads: 4, Extra: []string{"-p", "8080"}}), " ")
	want := "-l list.txt -json -silent -no-color -duc -probe -hash mmh3 -fhr -rl 10 -timeout 5 -t 4 -p 8080"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if strings.Contains(strings.Join(Args("l", Options{}), " "), "-fhr") {
		t.Error("redirects are not followed unless asked")
	}
}

func TestFormatHint(t *testing.T) {
	good := `{"url":"http://a.example.com","status_code":200}
{"url":"http://b.example.com","failed":true}
`
	events, unparsed, err := Parse(strings.NewReader(good))
	if err != nil || unparsed != 0 || len(events) != 2 {
		t.Fatalf("got %d events, %d unparsed, %v", len(events), unparsed, err)
	}
	if h := FormatHint(events, unparsed, "raw.jsonl"); h != "" {
		t.Errorf("good output got a hint: %s", h)
	}
	// status_code renamed to status, and a line that is not JSON
	renamed := `{"url":"http://a.example.com","status":200}
{"url":"http://b.example.com","status":403}
{"url":"http://c.example.com","failed":true}
not json
[INF] Current httpx version v1.6.10 (latest)
`
	events, unparsed, err = Parse(strings.NewReader(renamed))
	if err != nil || unparsed != 1 || len(events) != 3 {
		t.Fatalf("got %d events, %d unparsed, %v", len(events), unparsed, err)
	}
	want := "3 of 4 httpx results had no url and status_code or failed; the engine's output format may have changed. Read raw.jsonl for the full output"
	if h := FormatHint(events, unparsed, "raw.jsonl"); h != want {
		t.Errorf("got  %s\nwant %s", h, want)
	}
}
