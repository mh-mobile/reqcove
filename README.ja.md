# Reqcove

手元でも遠くでも、iPhone の HTTP(S) を AI エージェントに渡す道具。

[English](README.md)

iPhone は、あなたのコンピュータを Tailscale の **Exit Node** に選ぶ。そのコンピュータの上の Reqcove（バイナリ1つ）が通信を運び、許したホストだけを [mitmproxy](https://mitmproxy.org) で復号し、[MCP](https://modelcontextprotocol.io) でエージェントに渡す。iPhone でする設定は、Exit Node を選ぶことと、CA を一度だけ信頼することだけ。Wi-Fi でも 5G でも使える。

```
iPhone ──(tailnet、Exit Node)──▶ reqcove run ──SOCKS5──▶ mitmproxy ──▶ インターネット
                                     │                         │
                                     │                  アドオン：通信
                                     ▼                         ▼
                              エージェント ◀── MCP ── reqcove mcp ◀─ 記録（伏せ字）
```

Reqcove は RoamRun とは別の道具。RoamRun は遠くの端末を Xcode につなぐもので、通信は読まない。

> **まだ早い段階。** v0.1 はまだ出していない。ここに書いたことは、macOS（Apple シリコン）と Ubuntu 24.04（arm64）で、iPhone を使って試した。試していないことは、そう書いた。

## 要るもの

- Apple シリコンの macOS か、Linux（amd64 か arm64）
- [uv](https://docs.astral.sh/uv/)。Reqcove は、最初の起動のときに uv で mitmproxy（12.3.1）と Python を取ってくる。ほかに入れるものはない
- Tailscale の tailnet と、iPhone の Tailscale のアプリ

## 入れ方

リリースが出るまでは、ソースからビルドする（Go 1.27）。

```sh
git clone https://github.com/mh-mobile/reqcove && cd reqcove
go build -o reqcove ./cmd/reqcove
```

`go install …@version` は使えない。Reqcove は Tailscale の tsnet の fork を `replace` で使っているため。

## 使い方

1. コンピュータで起動する。運ぶ iPhone（`tailscale status` に出る名前）と、記録するホストを指定する。

   ```sh
   reqcove run --device iphone --allow-hosts 'api.example.com,*.example.com'
   ```

   初めてのときは、ログインの URL が出る。Tailnet Lock を使っていれば、署名する端末で実行する `tailscale lock sign nodekey:…` が出て、そのあと管理画面で Exit Node を承認するよう案内が出る。足りないことは、いつでも `reqcove status` が教える。
2. iPhone の Tailscale のアプリで、Exit Node に `reqcove` を選ぶ。
3. iPhone の Safari で `http://mitm.it` を開き（`http://` から手で打つ。そうしないと Safari が HTTPS で開こうとして警告が出ることがある）、iOS のプロファイルを入れ、設定 › 一般 › 情報 › 証明書信頼設定 で信頼する。CA の名前は `Reqcove CA (<コンピュータ>, <日付>)`。
4. エージェントに道具を渡す。Claude Code なら：

   ```sh
   claude mcp add reqcove -- reqcove mcp
   ```

   そのあと「この10分で api.example.com への要求で失敗したものは？」のように聞く。

Exit Node の代わりに、iPhone の Wi-Fi のプロキシ（手動）に、reqcove のノードの tailnet のアドレスとポート 8080（`--proxy-port`）を入れて使うこともできる。モバイル通信にはプロキシの設定がないので、こちらは Wi-Fi のときだけ。

### MCP の道具

| 道具 | |
|---|---|
| `list_flows` | 新しい順の通信。端末、ホスト（サブドメインも）、時刻（`since: "10m"`）、状態コード（`404`、`4xx`、`none`）、メソッドで絞る。ページ送り |
| `search_flows` | URL とヘッダーの文字を探す（`bodies` で本文の先頭も） |
| `get_flow` | 通信1件。本文は `bodies` のときだけ |
| `summarize` | ホスト、User-Agent、状態コード、メソッド、端末、Content-Type ごとの件数 |
| `list_devices` | 運んでいる端末、件数、最後の通信 |
| `list_tls_failures` | 端末が断った TLS。ピンニングのことが多いが、まだ信頼していない CA のこともある |
| `capture_stats` | mitmproxy の状態、記録が覆う期間、取りこぼし |
| `status` | 準備ができているか。できていなければ次の手順 |

### オプション

| | |
|---|---|
| `--device NAME` | 運ぶ端末。マシン名、端末の名前、tailnet のアドレス、StableID のどれか。繰り返して複数 |
| `--allow-hosts` | 復号して記録するホスト。`api.example.com`、`*.example.com`、全部なら `'*'`。付けないと、運ぶが何も記録しない |
| `--rules FILE` | `map_remote`、`map_local`、`modify_headers` を書いた YAML（mitmproxy の書き方）。許したホストにだけ当たる |
| `--web` | 代わりに mitmweb を `http://127.0.0.1:8081` で動かす（伏せ字なし、書き換えと送り直しができる、通信を持ち続ける） |
| `--dns` | Exit Node の DNS の問い合わせ先。既定は `1.1.1.1:53`。`system` で `/etc/resolv.conf` |
| `--no-redact` | 秘密を伏せずに記録する |
| `--state DIR` | 既定は `~/.reqcove`。ノードの鍵、CA とその秘密鍵が入る |

## 守ること、守らないこと

- 復号して記録するのは `--allow-hosts` のホストだけ。同じ接続の上のほかのホストへの要求は、数えるだけで記録しない。Apple のホストは、いつも復号せずに通す。
- 秘密は受け取った時点で伏せる：`Authorization`、`Proxy-Authorization`、名前にキーやトークンの印があるヘッダー、Cookie の値、秘密らしいクエリ（フラグメント、`Referer`、`Location` の中も）、エラーの文。**本文は伏せない。**
- エージェントが読んだものは、そのモデルの提供元に渡る。本文は外のサイトが書いたもので、エージェントを操ろうとすることがある。道具の説明にもそう書いてある。
- mitmproxy の SOCKS5 の口を使えるのは reqcove だけ（起動のたびに作るパスワード）。MCP のソケットと状態のフォルダは、自分の OS ユーザーだけが開ける。
- Exit Node は、このコンピュータ、その LAN、tailnet を宛先として断る。
- Tailscale にログを送らない。データプレーンの監査のログを求める tailnet には対応しない（`reqcove status` がそう言う）。

詳しくは [docs/SECURITY.md](docs/SECURITY.md)（英語）。

## できないこと

- 証明書をピンニングするアプリは復号できない（`list_tls_failures` に出る）。
- mitmproxy を通るのは TCP の 80 番と 443 番だけ。ほかのポートは、そのまま運ぶ。
- IPv6 は断る（アプリはすぐ IPv4 に回る）。QUIC は Apple 宛て以外を捨てるので、アプリは TCP に戻る。
- Exit Node 越しの通話は試していない。
- iPhone が使っている間に reqcove が止まると、reqcove が戻っても iPhone の DNS が止まったままになることがある（[tailscale#20870](https://github.com/tailscale/tailscale/issues/20870)）。そのときは Exit Node を一度オフにしてオンに戻す。
- コンピュータは起きている必要がある。`reqcove run` は macOS が操作のないときに眠るのを止めるが、蓋を閉じたときは止められない。

## こつ

- 新しいノードのたびに Exit Node を承認したくなければ、tailnet のポリシーに自動の承認を足す：`"autoApprovers": {"exitNode": ["you@example.com"]}`。
- 状態のフォルダが同じなら、CA も同じ。2台のコンピュータで1つの CA を使うなら、`~/.reqcove/mitmproxy/` をフォルダごと写す（秘密鍵が入っている）。
- `reqcove cleanup` が片付けの手順を出す。`--delete-state` で状態のフォルダを消す。

## ライセンス

MIT。Reqcove は Tailscale の fork（BSD-3-Clause）とほかのオープンソースのモジュールを使っている。リリースの tar.gz に、それぞれのライセンスを入れている。
