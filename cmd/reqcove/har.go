package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
)

// har writes the running reqcove's flows as a HAR 1.2 file to stdout, oldest
// first. It asks over the MCP socket with list_flows and get_flow, so the HAR
// holds what those tools return: masked as it arrived, body heads only.
func har(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("har", flag.ExitOnError)
	state := fs.String("state", defaultState(), "state directory")
	var in mcpserver.FilterIn
	fs.StringVar(&in.Device, "device", "", "only this device (name or StableID)")
	fs.StringVar(&in.Host, "host", "", "only this host and its subdomains")
	fs.StringVar(&in.Since, "since", "", "only requests started since: RFC 3339, or a duration ago such as 10m")
	fs.StringVar(&in.Until, "until", "", "only requests started until: RFC 3339, or a duration ago")
	fs.StringVar(&in.Status, "status", "", "only this status: 404, 4xx, or none")
	fs.StringVar(&in.Method, "method", "", "only this method")
	fs.StringVar(&in.UserAgent, "user-agent", "", "only requests whose User-Agent contains this, case-insensitive")
	limit := fs.Int("limit", 1000, "at most this many flows, the newest; 0 for all")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	conn, err := net.Dial("unix", filepath.Join(*state, "mcp.sock"))
	if err != nil {
		return fmt.Errorf("reqcove is not running: start `%s`, then export its flows", withState("reqcove run", *state))
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "reqcove-har", Version: version}, nil)
	session, err := client.Connect(ctx, &mcp.IOTransport{Reader: conn, Writer: conn}, nil)
	if err != nil {
		return err
	}
	defer session.Close()
	call := func(name string, args, out any) error {
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			return err
		}
		if res.IsError {
			for _, c := range res.Content {
				if t, ok := c.(*mcp.TextContent); ok {
					return errors.New(t.Text)
				}
			}
			return fmt.Errorf("%s failed", name)
		}
		b, _ := json.Marshal(res.StructuredContent)
		return json.Unmarshal(b, out)
	}

	var ids []string // newest first, as list_flows pages
	for page := (mcpserver.ListIn{FilterIn: in, PageIn: mcpserver.PageIn{Limit: 500}}); ; {
		var out mcpserver.ListOut
		if err := call("list_flows", page, &out); err != nil {
			return err
		}
		for _, f := range out.Flows {
			ids = append(ids, f.ID)
		}
		if out.NextCursor == 0 || *limit > 0 && len(ids) >= *limit {
			break
		}
		page.Cursor = out.NextCursor
	}
	if *limit > 0 && len(ids) > *limit {
		ids = ids[:*limit]
	}

	var stats mcpserver.StatsOut
	if err := call("capture_stats", nil, &stats); err != nil {
		return err
	}
	comment := "masked as it arrived; bodies are their kept heads"
	if r, _ := stats.Stats["redacting"].(bool); !r {
		comment = "NOT masked: reqcove run --no-redact; bodies are their kept heads"
		fmt.Fprintln(os.Stderr, "the flows are not masked (reqcove run --no-redact): check before sharing the file")
	}
	w := bufio.NewWriter(os.Stdout)
	fmt.Fprintf(w, `{"log":{"version":"1.2","creator":{"name":"reqcove","version":%q},"comment":%q,"entries":[`, version, comment)
	n := 0
	for i := len(ids) - 1; i >= 0; i-- {
		var v capture.FlowView
		if err := call("get_flow", mcpserver.GetIn{ID: ids[i], Bodies: true}, &v); err != nil {
			if strings.Contains(err.Error(), "no flow") { // get_flow's (Store.Get's) words
				continue // evicted since the list
			}
			return err
		}
		b, err := json.Marshal(harEntry(v))
		if err != nil {
			return err
		}
		if n > 0 {
			w.WriteString(",")
		}
		w.Write(b)
		n++
	}
	w.WriteString("]}}\n")
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%d flows\n", n)
	return nil
}

type harNV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harPost struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Encoding string `json:"_encoding,omitempty"` // HAR has no encoding for postData
	Comment  string `json:"comment,omitempty"`
}

type harContent struct {
	Size     int64  `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

type harReq struct {
	Method      string   `json:"method"`
	URL         string   `json:"url"`
	HTTPVersion string   `json:"httpVersion"`
	Cookies     []harNV  `json:"cookies"`
	Headers     []harNV  `json:"headers"`
	QueryString []harNV  `json:"queryString"`
	PostData    *harPost `json:"postData,omitempty"`
	HeadersSize int      `json:"headersSize"`
	BodySize    int64    `json:"bodySize"`
}

type harResp struct {
	Status      int        `json:"status"`
	StatusText  string     `json:"statusText"`
	HTTPVersion string     `json:"httpVersion"`
	Cookies     []harNV    `json:"cookies"`
	Headers     []harNV    `json:"headers"`
	Content     harContent `json:"content"`
	RedirectURL string     `json:"redirectURL"`
	HeadersSize int        `json:"headersSize"`
	BodySize    int64      `json:"bodySize"`
	Error       string     `json:"_error,omitempty"`
}

type harTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

type harEntryOut struct {
	Started  string     `json:"startedDateTime"`
	Time     float64    `json:"time"`
	Request  harReq     `json:"request"`
	Response harResp    `json:"response"`
	Cache    struct{}   `json:"cache"`
	Timings  harTimings `json:"timings"`
	Conn     string     `json:"connection,omitempty"`
	Device   string     `json:"_device,omitempty"`
	Comment  string     `json:"comment,omitempty"`
}

func harEntry(v capture.FlowView) harEntryOut {
	ms := 0.0
	if v.End > v.Start {
		ms = (v.End - v.Start) * 1000
	}
	e := harEntryOut{
		Started: time.Unix(0, int64(v.Start*1e9)).Format(time.RFC3339Nano),
		Time:    ms,
		Request: harReq{Method: v.Method, URL: v.URL, HTTPVersion: v.HTTPVersion, Cookies: []harNV{},
			Headers: nv(v.ReqHeaders), QueryString: query(v.URL), HeadersSize: -1, BodySize: v.ReqBody.Size},
		Response: harResp{Status: v.Status, StatusText: v.Reason, HTTPVersion: v.HTTPVersion, Cookies: []harNV{},
			Headers: nv(v.RespHeaders), RedirectURL: header(v.RespHeaders, "location"), HeadersSize: -1, BodySize: v.RespBody.Size, Error: v.Error},
		Timings: harTimings{Wait: ms},
		Conn:    v.Conn,
		Device:  v.DeviceName,
	}
	if e.Device == "" {
		e.Device = v.Device
	}
	if v.Status == 0 {
		e.Response.BodySize = -1 // no response
	}
	var notes []string
	if v.State == "open" {
		notes = append(notes, "still open when exported")
	}
	if v.ReqBody.Size > 0 || v.ReqBodyText != "" || v.ReqBodyEnc != "" {
		text, enc, note := harBody(v.ReqBodyText, v.ReqBodyEnc, v.ReqBody)
		e.Request.PostData = &harPost{MimeType: header(v.ReqHeaders, "content-type"), Text: text, Encoding: enc, Comment: note}
	}
	text, enc, note := harBody(v.RespBodyText, v.RespBodyEnc, v.RespBody)
	size := v.RespBody.Size // on the wire; HAR's is decoded, known when all of it is kept
	if v.RespBody.Final && !v.RespBody.Truncated && v.RespBody.Decoded && note == "" {
		size = int64(len(text))
		if b, err := base64.StdEncoding.DecodeString(text); enc == "base64" && err == nil {
			size = int64(len(b))
		}
	}
	e.Response.Content = harContent{Size: size, MimeType: header(v.RespHeaders, "content-type"), Text: text, Encoding: enc, Comment: note}
	if v.MappedURL != "" {
		notes = append(notes, "sent to "+v.MappedURL)
	}
	if v.Mocked {
		notes = append(notes, "answered by a reqcove mock rule, not the server")
	}
	for _, r := range v.Rewrites {
		notes = append(notes, "rule: "+r)
	}
	if v.WSMessages > 0 {
		notes = append(notes, fmt.Sprintf("WebSocket: %d messages, %d bytes (not in the HAR)", v.WSMessages, v.WSBytes))
	}
	notes = append(notes, v.Notes...)
	e.Comment = strings.Join(notes, "; ")
	return e
}

// harBody is a body head as get_flow returned it: text, base64, or omitted
// (not text while masking), with a note when it is only the head.
func harBody(text, enc string, b capture.Body) (string, string, string) {
	var notes []string
	if enc != "" && enc != "base64" { // the omitted message
		notes = append(notes, enc)
		text, enc = "", ""
	}
	if b.Truncated {
		notes = append(notes, fmt.Sprintf("only the first part of the body is kept (%d bytes on the wire)", b.Size))
	} else if !b.Final && b.Size > 0 {
		notes = append(notes, "the body had not ended")
	}
	if !b.Decoded && text != "" {
		notes = append(notes, "not decoded: the bytes as sent (Content-Encoding "+b.Encoding+")")
	}
	if b.Note != "" {
		notes = append(notes, b.Note)
	}
	return text, enc, strings.Join(notes, "; ")
}

func nv(h [][2]string) []harNV {
	out := make([]harNV, 0, len(h))
	for _, kv := range h {
		out = append(out, harNV{kv[0], kv[1]})
	}
	return out
}

func header(h [][2]string, name string) string {
	for _, kv := range h {
		if strings.EqualFold(kv[0], name) {
			return kv[1]
		}
	}
	return ""
}

func query(raw string) []harNV {
	out := []harNV{}
	u, err := url.Parse(raw)
	if err != nil {
		return out
	}
	q := u.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range q[k] {
			out = append(out, harNV{k, v})
		}
	}
	return out
}
