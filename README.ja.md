# Reqcove

[![test](https://github.com/mh-mobile/reqcove/actions/workflows/test.yml/badge.svg)](https://github.com/mh-mobile/reqcove/actions/workflows/test.yml)
[![release](https://img.shields.io/github/v/release/mh-mobile/reqcove)](https://github.com/mh-mobile/reqcove/releases)
[![license](https://img.shields.io/github/license/mh-mobile/reqcove)](LICENSE)

iPhone の HTTP(S) 通信を、手元にあっても離れた場所にあっても、AI エージェントに渡すツールです。

Reqcove（レクコーブ）という名称は、request（リクエスト）と cove（入り江）を組み合わせた造語です。リクエストが集まる入り江、というイメージです。

[English](README.md)

iPhone は、あなたのコンピュータを Tailscale の **Exit Node** として選びます。そのコンピュータ上で動く Reqcove（単一のバイナリ）が通信を中継し、許可したホストの通信を [mitmproxy](https://mitmproxy.org) で復号して、フローを [MCP](https://modelcontextprotocol.io) でエージェントに提供します。iPhone 側で必要な設定は、Exit Node を選ぶことと、CA を一度信頼することだけです。Wi-Fi でも 5G でも使えます。

```text
iPhone ──(tailnet, Exit Node)──▶ reqcove run ──SOCKS5──▶ mitmproxy ──▶ インターネット
                                     │                       │
                                     │                アドオン: フロー
                                     ▼                       ▼
                              agent ◀── MCP ── reqcove mcp ◀─ 記録（マスク済み）
```

Reqcove は RoamRun とは別のツールです。RoamRun は遠くにあるデバイスを Xcode につなぐためのもので、通信は読みません。

> **開発状況：初期段階です**（v0.1）。macOS（Apple シリコン）と Ubuntu 24.04（arm64）で、iPhone を使って試しました。試していないことは、ドキュメントにその旨を書いています。以下には v0.1.0 より新しいものも含まれます（[CHANGELOG](CHANGELOG.md)）。次のリリースまでは、ソースからビルドしてください。

## 必要なもの

- Apple シリコンの macOS、または Linux（amd64 または arm64）
- [uv](https://docs.astral.sh/uv/)。初回起動時に、Reqcove が uv を使って mitmproxy（12.3.1）と Python を取得します。ほかにインストールするものはありません
- Tailscale の tailnet と、iPhone にインストールした Tailscale アプリ

## インストール

Homebrew で入れます（macOS と Linux。ソースからビルドし、uv も一緒に入ります）。

```sh
brew install mh-mobile/tap/reqcove
```

[Releases](https://github.com/mh-mobile/reqcove/releases) からバイナリを落として使うこともできます（macOS の Apple silicon、Linux の amd64 と arm64）。その場合、uv は自分で入れてください。macOS のバイナリは、Developer ID で署名し、Apple の公証（notarization）を受けています。ブラウザでダウンロードしたものも、そのまま動きます。

ソースからビルドすることもできます（Go 1.27）。

```sh
git clone https://github.com/mh-mobile/reqcove && cd reqcove
go build -o reqcove ./cmd/reqcove
```

`go install …@version` は使えません。Reqcove は Tailscale の tsnet の fork を `replace` ディレクティブで使っているためです。
## 使い方

1. コンピュータ側で起動します。中継する iPhone（`tailscale status` に表示される名前）と、記録するホストを指定します。

   ```sh
   reqcove run --device iphone --allow-hosts 'api.example.com,*.example-cdn.com'
   ```

   初回はログイン用の URL が表示され、続けてほかに必要なこと（Exit Node の承認、Tailnet Lock）が表示されます。不足しているものは `reqcove status` でいつでも確認できます。
2. iPhone の Tailscale アプリで、Exit Node に `reqcove` を選びます。
3. 同じく iPhone で、Reqcove の CA を信頼します。`reqcove run` が表示する QR コードをカメラで読み（または Safari で `http://mitm.it` を、`http://` から入力して開き）、プロファイルをインストールして（設定 › プロファイルがダウンロード済み）、設定 › 一般 › 情報 › 証明書信頼設定 で信頼します（名前は `Reqcove CA (<コンピュータ名>, <日付>)`）。
4. エージェントに、MCP ツールと、その使い方を教える Skill を入れます。Claude Code の場合：

   ```sh
   claude mcp add reqcove -- reqcove mcp
   reqcove init   # v0.1.0 にはまだありません
   ```

   あとは「この 10 分間で api.example.com へのリクエストのうち、失敗したものは？」のように聞いてみてください。

v0.1.0 のあとは、`reqcove run` をエージェントをつなぎ直さずに起動し直せます（記録は空から始まります）。`reqcove cleanup` は、すべてを元に戻す手順を表示します。

### MCP ツール

| ツール | |
|---|---|
| `summarize` | ホスト、User-Agent、ステータスコード、デバイスごとの件数。まず何があるかを見る |
| `list_flows` | フローを新しい順に。デバイス、ホスト、時間（`since: "10m"`）、ステータスコード、メソッド、User-Agent で絞り込み |
| `search_flows` | URL とヘッダー（とボディ）の中の文字を検索 |
| `get_flow` | フローを 1 件。ボディは頼んだときだけ |
| `list_devices` | 中継しているデバイス |
| `list_tls_failures` | デバイスが拒否した TLS ハンドシェイク。多くは証明書ピンニングか、まだ信頼されていない CA |
| `list_passthrough` | `--pass-hosts` のホストへの接続。ホスト、宛先、時刻、送受信の量 |
| `capture_stats` | mitmproxy の状態、記録がカバーしている期間 |
| `status` | セットアップが完了しているか。未完了なら次の手順 |

詳しくは[ガイド](docs/guide.ja.md#mcp-ツール)にあります。

### オプション

| | |
|---|---|
| `--device NAME` | 中継するデバイス（`tailscale status` の名前）。複数なら繰り返す |
| `--allow-hosts` | 復号して記録するホスト。`api.example.com`、`*.example.com`、すべてなら `'*'`、`@ファイル` |
| `--pass-hosts` | 許可したホストのうち、復号せずに通すもの。証明書ピンニングをするアプリのため |
| `--rules FILE` | 許可したホストへのリクエストの行き先を書き換える（`map_remote`、`map_local` など） |
| `--upstream-proxy URL` | 復号したリクエストを Burp Suite などのプロキシに回す |
| `--local-proxy` | このコンピュータ自身のアプリ（iOS シミュレーターなど）も記録する。macOS では、`run` の間、システムの Web プロキシを Reqcove に向ける |
| `--ui` | 記録を iPhone 自身で見るページ |
| `--web` | 代わりに mitmweb を使う（マスクなし） |
| `--mcp-http` | ツールを HTTP でも出す。ほかの端末のエージェント（Grok Bot）用 |
| `--state DIR` | ノードの鍵と CA を置く場所。既定は `~/.reqcove` |

すべてのオプションと、それぞれの詳しい説明は[ガイド](docs/guide.ja.md#オプション)にあります。

### ほかの使い方

- [ルール](docs/guide.ja.md#ルール)：アプリのリクエストを開発サーバーに送る、ファイルで答える
- [記録を iPhone で見る](docs/guide.ja.md#記録を-iphone-で見る--ui)（`--ui`）
- [iOS シミュレーター](docs/guide.ja.md#ios-シミュレーター--local-proxy)（`--local-proxy`）
- [HAR ファイルに書き出す](docs/guide.ja.md#har-ファイルに書き出す)（`reqcove har`）
- [Web アプリのバックエンド](docs/guide.ja.md#web-アプリのバックエンドrails-など)（Rails など）
- [上流のプロキシ](docs/guide.ja.md#上流のプロキシburp-suite-など)（Burp Suite など）
- [証明書ピンニング](docs/guide.ja.md#証明書ピンニング)（`--pass-hosts`）
- [ほかの端末のエージェント](docs/guide.ja.md#ほかの端末のエージェント--mcp-http)、Grok Bot など（`--mcp-http`）
- [エージェント用の Skill](docs/guide.ja.md#エージェント用の-skillreqcove-init)（`reqcove init`）
- [1 台で複数の Exit Node](docs/several-exit-nodes.ja.md)、[コンテナ](docs/container.ja.md)、[別の Mac をデバイスに](docs/another-mac.ja.md)

## セキュリティ

- 復号して記録するのは `--allow-hosts` のホストだけです。Apple のホストは、常に復号せずに通します。
- 秘密（トークン、鍵、Cookie、パスワード）は、届いた時点でマスクします。**ボディの中で、秘密と分からない名前の下にある秘密は見つけられません。** メールアドレスなどの個人情報もマスクしません。
- エージェントが読んだものは、そのモデルの提供元に送られます。ボディは外部のサイトが書いたもので、エージェントに指示しようとすることがあります。
- Exit Node は、このコンピュータ、LAN、tailnet を宛先として拒みます。

詳しくは [docs/SECURITY.md](docs/SECURITY.md) を見てください（英語）。

## 制限事項

- 証明書ピンニングを行うアプリは、Reqcove の証明書を拒みます。[証明書ピンニング](docs/guide.ja.md#証明書ピンニング)を見てください。
- mitmproxy を通るのは TCP の 80 番と 443 番ポートだけです。ほかのポートはそのまま中継します。
- IPv6 は拒否し、QUIC は（Apple 宛て以外）ドロップします。アプリは IPv4 と TCP にフォールバックします。
- iPhone から、このコンピュータや LAN には直接届きません。許可したホストへのリクエストを、ルールでそこへ送ることはできます。
- iPhone が使用中に reqcove が停止すると、iPhone の DNS が止まったままになることがあります（[tailscale#20870](https://github.com/tailscale/tailscale/issues/20870)）。Exit Node を一度オフにして、オンに戻してください。
- コンピュータはスリープさせないでください。`reqcove run` は macOS のアイドルスリープを防ぎますが、蓋を閉じたときのスリープは防げません。

ほかの制限事項は[ガイド](docs/guide.ja.md#そのほかの制限事項)にあります。

## ライセンス

MIT。Reqcove は Tailscale の fork（BSD-3-Clause）とそのほかのオープンソースモジュールを使っています。リリースのアーカイブにはそれらのライセンスを同梱しています。
