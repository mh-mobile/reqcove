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
// gRPC-Web's text form (base64) is not read as frames.
func isGRPC(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	return (strings.HasPrefix(ct, "application/grpc") || strings.HasPrefix(ct, "application/connect+")) && !strings.HasPrefix(ct, "application/grpc-web-text")
}

const grpcMaxFrames = 4096

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

// grpcFrames reads the frames in a head, at most grpcMaxFrames; one cut by
// the head's end comes last, with no payload. nil if the head is not framed
// (a flag gRPC does not use: 1 compressed, 2 Connect's end of stream, 0x80
// gRPC-Web's trailers). Never
// allocates by a length a site declared.
func grpcFrames(head []byte) []grpcFrame {
	var out []grpcFrame
	for i := 0; i+5 <= len(head) && len(out) < grpcMaxFrames; {
		if head[i]&^0x83 != 0 {
			return nil
		}
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
// line) and masked as JSON; protobuf ones rendered (renderProto). gRPC-Web's trailer frame gives
// trailers, its lines masked as headers are.
// Not framed after all (a text body under such a type): masked as a body.
// Without masking (redact false), the head stays as it came.
// Protobuf messages are rendered (renderProto) while masking.
func (s *Store) grpcBody(head []byte, ct, path string, request, redact, cut bool) (out []byte, note string, trailers [][2]string, view string) {
	frames := grpcFrames(head)
	if len(frames) == 0 {
		if !redact {
			return head, "", nil, ""
		}
		return maskBody(head, ct, request), "", nil, ""
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
		case f.flag&2 != 0 && f.flag&1 == 0 && f.payload != nil: // Connect's end of stream: JSON (its error, its trailers), whatever the codec
			lines = append(lines, "[end of stream] "+string(maskBody(f.payload, "application/json", request)))
			continue
		case f.flag&1 != 0:
			compressed++
			lines = append(lines, fmt.Sprintf("[compressed, %d bytes]", f.size))
		case f.payload == nil:
			lines = append(lines, fmt.Sprintf("[cut: %d bytes]", f.size))
		case framedJSON(ct):
			lines = append(lines, string(f.payload))
		default:
			var r []byte
			r, view = renderProto(f.payload, ct, path, request, false)
			lines = append(lines, string(r))
		}
		sizes = append(sizes, fmt.Sprint(f.size))
	}
	if len(trailers) > 0 {
		trailers = s.maskHeaders(trailers)
	}
	shown := sizes
	if len(shown) > 32 {
		shown = append(shown[:32:32], "…")
	}
	note = fmt.Sprintf("gRPC: %d messages (%s bytes)", len(sizes), strings.Join(shown, ", "))
	if len(frames) == grpcMaxFrames {
		note = fmt.Sprintf("gRPC: the first %d messages (%s bytes), more not read", len(sizes), strings.Join(shown, ", "))
	}
	if compressed > 0 {
		note += fmt.Sprintf(", %d compressed (not read)", compressed)
	}
	if !redact {
		return head, note, trailers, ""
	}
	text := strings.Join(lines, "\n")
	if !framedJSON(ct) {
		return []byte(text), note + "; one message after another", trailers, view
	}
	return maskBody([]byte(text), "application/json", request), note + "; de-framed: one message a line", trailers, ""
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
