package capture

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
)

// gRPC (and gRPC-Web, Connect's streams) frame each message: a flag byte (1:
// compressed, 0x80: gRPC-Web's trailers) and a 4-byte length. Their status
// comes in the response's headers when there is no message (a trailers-only
// answer, the usual UNAUTHENTICATED), else in its trailers (HTTP/2's, or
// gRPC-Web's last frame).

// isGRPC: a gRPC, gRPC-Web or Connect streaming content type, framed so.
func isGRPC(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	return strings.HasPrefix(ct, "application/grpc") || strings.HasPrefix(ct, "application/connect+")
}

// framedJSON: the framed messages are JSON (grpc+json, connect+json).
func framedJSON(ct string) bool {
	ct, _, _ = strings.Cut(strings.ToLower(ct), ";")
	return isGRPC(ct) && strings.HasSuffix(strings.TrimSpace(ct), "+json")
}

type grpcFrame struct {
	flag    byte
	payload []byte // nil when the frame is cut by the head's end
	size    int    // its declared length
}

// grpcFrames reads the frames in a head, at most 4096 of them; one cut by the
// head's end comes last, with no payload. Never allocates by a length a site
// declared.
func grpcFrames(head []byte) []grpcFrame {
	var out []grpcFrame
	for i := 0; i+5 <= len(head) && len(out) < 4096; {
		n := int(binary.BigEndian.Uint32(head[i+1 : i+5]))
		f := grpcFrame{flag: head[i], size: n}
		if n > len(head)-i-5 {
			out = append(out, f)
			break
		}
		f.payload = head[i+5 : i+5+n]
		out = append(out, f)
		i += 5 + n
	}
	return out
}

// grpcBody masks a framed body's head: JSON messages de-framed (one per
// line) and masked as JSON; others described, their bytes kept as they are
// (not text: never handed out while masking). gRPC-Web's trailer frame gives
// trailers, its lines masked as headers are.
func (s *Store) grpcBody(head []byte, ct string, request bool) (out []byte, note string, trailers [][2]string) {
	frames := grpcFrames(head)
	if len(frames) == 0 {
		return head, "", nil
	}
	var lines []string
	var sizes []string
	compressed := 0
	for _, f := range frames {
		switch {
		case f.flag&0x80 != 0:
			if f.payload != nil {
				for _, l := range strings.Split(string(f.payload), "\r\n") {
					if k, v, ok := strings.Cut(l, ":"); ok {
						trailers = append(trailers, [2]string{strings.TrimSpace(k), strings.TrimSpace(v)})
					}
				}
			}
			continue
		case f.flag&1 != 0:
			compressed++
			lines = append(lines, fmt.Sprintf("[compressed, %d bytes]", f.size))
		case f.payload == nil:
			lines = append(lines, fmt.Sprintf("[cut: %d bytes]", f.size))
		default:
			lines = append(lines, string(f.payload))
		}
		sizes = append(sizes, fmt.Sprint(f.size))
	}
	if len(trailers) > 0 {
		trailers = s.maskHeaders(trailers)
	}
	note = fmt.Sprintf("gRPC: %d messages (%s bytes)", len(sizes), strings.Join(sizes, ", "))
	if compressed > 0 {
		note += fmt.Sprintf(", %d compressed (not read)", compressed)
	}
	if !framedJSON(ct) {
		return head, note, trailers
	}
	text := strings.Join(lines, "\n")
	return maskBody([]byte(text), "application/json", request), note + "; de-framed: one message a line", trailers
}

// grpcStatus is a flow's gRPC status: its response headers' (trailers-only),
// else its trailers', "pending" while a gRPC flow has neither yet.
func grpcStatus(f *Flow) (status, message string) {
	for _, h := range [][][2]string{f.RespHeaders, f.RespTrailers} {
		if st := header(h, "grpc-status"); st != "" {
			return st, header(h, "grpc-message")
		}
	}
	if f.State == "open" && (isGRPC(header(f.ReqHeaders, "content-type")) || isGRPC(header(f.RespHeaders, "content-type"))) {
		return "pending", ""
	}
	return "", ""
}

// grpcHeaderValue masks gRPC's metadata conventions: a *-bin value is base64
// binary (its size only), and grpc-message is percent-encoded text (decoded,
// then masked, at most 1 KiB).
func grpcHeaderValue(name, v string, mask func(string) string) (string, bool) {
	switch {
	case strings.HasSuffix(name, "-bin"):
		n := len(v) * 3 / 4
		if b, err := base64.StdEncoding.DecodeString(v); err == nil {
			n = len(b)
		} else if b, err := base64.RawStdEncoding.DecodeString(v); err == nil {
			n = len(b)
		}
		return fmt.Sprintf("[binary %d bytes]", n), true
	case name == "grpc-message":
		if d, err := url.PathUnescape(v); err == nil {
			v = d
		}
		return cutTo(mask(v), 1<<10), true
	}
	return v, false
}
