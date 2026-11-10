package main

import (
	"os"
	"strings"
	"testing"

	"github.com/mh-mobile/reqcove/internal/capture"
)

// TestDockerfileInStep: the image fetches mitmproxy and Python with the
// arguments run gives uvx, or the container, offline at run time, cannot start.
func TestDockerfileInStep(t *testing.T) {
	b, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	want := "uvx --python " + defaultPython + " --exclude-newer " + capture.UVExcludeNewer + " --from " + defaultMitmSpec + " "
	if !strings.Contains(string(b), want) {
		t.Errorf("the Dockerfile does not fetch with %q", want)
	}
}
