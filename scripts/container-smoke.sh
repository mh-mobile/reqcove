#!/bin/sh
# Checks the container image without a tailnet login (CI, and by hand):
#   scripts/container-smoke.sh [image]     (default: builds reqcove:smoke)
# The run container has no network: mitmproxy must start from what the image
# holds. Docker by default; CONTAINER=podman for Podman.
set -eu
c=${CONTAINER:-docker}
img=${1:-}
if [ -z "$img" ]; then
	img=reqcove:smoke
	$c build -t "$img" .
fi
vol=reqcove-smoke-$$
run=reqcove-smoke-$$
cleanup() { $c rm -f "$run" "$run-2" >/dev/null 2>&1 || :; $c volume rm "$vol" >/dev/null 2>&1 || :; }
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; $c logs "$run" >&2 2>&1 || :; exit 1; }

$c run --rm "$img" version | grep -q '^reqcove ' || fail "reqcove version"

$c volume create "$vol" >/dev/null
$c run -d --init --network none --name "$run" -v "$vol:/home/nonroot/.reqcove" "$img" \
	run --device ci --allow-hosts example.com --hostname reqcove-smoke --web >/dev/null
for _ in $(seq 120); do
	$c logs "$run" 2>&1 | grep -q 'MCP on ' && break
	[ "$($c inspect -f '{{.State.Running}}' "$run")" = true ] || fail "run exited"
	sleep 1
done
$c logs "$run" 2>&1 | grep -q 'mitmproxy 12.3.1 ready' || fail "mitmproxy did not start offline"
$c logs "$run" 2>&1 | grep -q 'mitmweb on http://127.0.0.1:8081/' || fail "mitmweb (--web) did not start"

# The state directory a new volume got: nonroot's, 0700.
perm=$($c run --rm --network none -v "$vol:/s" debian:trixie-slim stat -c '%u %a' /s)
[ "$perm" = "65532 700" ] || fail "state directory is $perm, want 65532 700"

# reqcove mcp from another container, as an agent would: the socket in the volume.
init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
ready='{"jsonrpc":"2.0","method":"notifications/initialized"}'
call='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"capture_stats","arguments":{}}}'
out=$( (printf '%s\n%s\n%s\n' "$init" "$ready" "$call"; sleep 3) | \
	$c run -i --rm --network none --log-driver none --volumes-from "$run" "$img" mcp)
echo "$out" | grep -q '\\"state\\":\\"ready\\"\|"state":"ready"' || fail "reqcove mcp through the volume: $out"

# reqcove status by docker exec, as the docs say.
$c exec "$run" reqcove status | grep -q 'reqcove is running' || fail "docker exec reqcove status"

# A second run on the same volume is refused (the lock holds across containers).
if $c run --name "$run-2" --network none -v "$vol:/home/nonroot/.reqcove" "$img" \
	run --device ci --allow-hosts example.com >/dev/null 2>&1; then
	fail "a second run on the same state started"
fi
$c logs "$run-2" 2>&1 | grep -qi 'another reqcove' || fail "the second run did not say why: $($c logs "$run-2" 2>&1 | tail -1)"

# docker stop: SIGTERM, a clean exit within the grace period.
$c stop "$run" >/dev/null
code=$($c inspect -f '{{.State.ExitCode}}' "$run")
[ "$code" = 0 ] || fail "exit code $code after stop"

$c image ls "$img" --format '{{.Repository}}:{{.Tag}} {{.Size}}'
echo ok
