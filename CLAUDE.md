# Reqcove（フォルダ名の far-traffic は仮）

遠くの iPhone の HTTP(S) を、Tailscale の Exit Node と mitmproxy で復号し、MCP で AI エージェントに渡す OSS。使い方は `README.md`、安全の考え方は `docs/SECURITY.md`。

手元に `NOTES.md` と `docs/plan.ja.md` があれば、先に読むこと（経緯、試した結果、計画と進み具合。どちらもリポジトリには入れていない）。

## 作り

- `cmd/reqcove`：`run`、`status`、`cleanup`、`mcp`、`version`。
- `internal/exitnode`：tsnet の Exit Node（Tailscale の fork を `go.mod` の `replace` で使う）、振り分け、Remote Proxy、状態と次の手順。
- `internal/capture`：mitmdump を uvx で子として動かし、埋め込みのアドオン（`addon.py`）から通信を受けて記録する（伏せ字、範囲、上限）。
- `internal/mcpserver`：MCP の道具と、Unix ソケットの中継。

## テスト

- `go test ./...`：ふつうのテスト（CI で macOS と Linux）。
- `REQCOVE_E2E=1`：本物の mitmproxy を uvx で使う（CI でも回す）。
- `REQCOVE_TRIAL2=1`（メモリの試し）、`REQCOVE_SOAK=4h`（長い試し）、`REQCOVE_UDP_MEASURE=1`（UDP の測り）：手元だけ。
- 直したら、直しを外すとテストが落ちることを確かめる。

## 決まり

- 返事は日本語で書く。
- iPhone や VM（tart の `ubuntu-standin`）で何かする前に、ユーザーに聞く。
- ~/Documents や ~/Desktop は探さない。
- ドキュメントには、裏の取れたことだけを書く。試していないことは、そう書く。
- 外に出ること（リポジトリの公開、タグ、リリース、上流への issue や PR）は、ユーザーに聞いてから。
