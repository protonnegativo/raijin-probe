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
