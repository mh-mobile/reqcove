package main

import (
	"os"
	"strings"
	"testing"

	"github.com/mh-mobile/reqcove/internal/capture"
)

// TestDockerfileInStep: the image fetches mitmproxy and Python as run starts
// them (uv run with the launcher at the state directory's path), or the
// container, offline at run time, cannot start.
func TestDockerfileInStep(t *testing.T) {
	b, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	_, args := capture.PyCommand(capture.Config{Uvx: "uvx", Python: defaultPython, MitmSpec: defaultMitmSpec, Dir: "/home/nonroot/.reqcove"}, "mitmdump")
	want := "uv " + strings.Join(args, " ") + " --version"
	if !strings.Contains(string(b), want) {
		t.Errorf("the Dockerfile does not fetch with %q", want)
	}
}
