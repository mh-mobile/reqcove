# Reqcove in a container: docs/container.md. Docker and Podman build it as is.
#
# The final image is distroless (glibc and little else: no shell, no package
# manager), as the user nonroot (65532). mitmproxy and Python are fetched at
# build time, with the arguments reqcove runs them with (TestDockerfileInStep
# checks they match), and found offline at run time (UV_OFFLINE).
#
# Base images by digest; Dependabot proposes updates.

# The release's version, for `reqcove version`.
ARG VERSION=dev

FROM ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490 AS uv

FROM --platform=$BUILDPLATFORM golang:1.27.4-trixie@sha256:b54b2639de8c1bfe538ec5ffc45f29b1932235ac5f6d63c059853646677112d9 AS build
ARG TARGETOS TARGETARCH VERSION
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY skills ./skills
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/reqcove ./cmd/reqcove

# Python and mitmproxy, fetched as the user that runs them, into /opt/uv.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS mitmproxy
COPY --from=uv /uv /uvx /usr/local/bin/
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
 && install -d -o 65532 -g 65532 /opt/uv /home/nonroot \
 && install -d -o 65532 -g 65532 -m 0700 /home/nonroot/.reqcove
ENV HOME=/home/nonroot UV_CACHE_DIR=/opt/uv/cache UV_PYTHON_INSTALL_DIR=/opt/uv/python UV_PYTHON_PREFERENCE=only-managed
USER 65532:65532
# As run starts mitmproxy: its launcher and lock in the state directory, then
# uv run --locked (hashes checked). uv keys the environment by the script's
# path, so this is the path run writes them to; run writes them again.
COPY --chown=65532:65532 internal/capture/mitm.py internal/capture/mitm.py.lock /home/nonroot/.reqcove/
RUN uv run --locked --no-project --python 3.14 --script /home/nonroot/.reqcove/mitm.py mitmdump --version \
 && rm /home/nonroot/.reqcove/mitm.py /home/nonroot/.reqcove/mitm.py.lock \
 && test ! -e /home/nonroot/.mitmproxy
# uv's entry points start with #!/bin/sh and a line of shell that runs the
# env's python (a trampoline), and distroless has no shell: point them at that
# python. The lines after the first are a string to Python, so the scripts run
# as they are. Only uv's trampolines (second line '''exec'); the build stops if
# another #!/bin/sh script is there, which could not run in the image.
# ponytail: a sed on uv's script format; a change of it stops the build here.
RUN for f in /opt/uv/cache/archive-v0/*/bin/*; do \
      [ -f "$f" ] && [ "$(sed -n 1p "$f")" = '#!/bin/sh' ] || continue; \
      case "$(sed -n 2p "$f")" in "'''exec' "*) sed -i "1s|.*|#!$(dirname "$f")/python|" "$f" ;; \
        *) echo "a shell script uv's rewrite does not know: $f" >&2; exit 1 ;; esac; \
    done

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:cc66d222f0a7ec996b78a99fe76a969bc80b539a5016ad866c14d1949bc6d0ab
COPY --from=uv /uv /uvx /usr/local/bin/
COPY --from=mitmproxy --chown=65532:65532 /opt/uv /opt/uv
# The state directory, 0700 and nonroot's: a new named volume takes both.
COPY --from=mitmproxy --chown=65532:65532 /home/nonroot/.reqcove /home/nonroot/.reqcove
COPY --from=build /out/reqcove /usr/local/bin/reqcove
# REQCOVE_CONTAINER: run tells agents to connect through docker run (podman run under Podman), not reqcove mcp here.
ENV HOME=/home/nonroot UV_CACHE_DIR=/opt/uv/cache UV_PYTHON_INSTALL_DIR=/opt/uv/python UV_PYTHON_PREFERENCE=only-managed UV_OFFLINE=1 REQCOVE_CONTAINER=1
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/reqcove"]
