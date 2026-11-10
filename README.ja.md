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

[Releases](https://github.com/mh-mobile/reqcove/releases) からバイナリをダウンロードして使うこともできます（Apple シリコンの macOS、Linux の amd64 と arm64）。その場合、uv は自分で入れてください。macOS のバイナリは、Developer ID で署名し、Apple の公証（notarization）を受けています。ブラウザでダウンロードしたものも、そのまま動きます。

ソースからビルドすることもできます（Go 1.27）。

```sh
git clone https://github.com/mh-mobile/reqcove && cd reqcove
go build -o reqcove ./cmd/reqcove
```

できた `reqcove` は、`PATH` の通ったディレクトリに置いてください（または `./reqcove` として実行します）。

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
   reqcove init
   ```

   あとは「この 10 分間で api.example.com へのリクエストのうち、失敗したものは？」のように聞いてみてください。

エージェントは、`summarize`、`list_flows`、`search_flows`、`get_flow` などの MCP ツールで記録を読みます（[ツールの一覧](docs/guide.ja.md#mcp-ツール)）。`reqcove cleanup` は、すべてを元に戻す手順を表示します。停止・再起動・アップデートは[ガイド](docs/guide.ja.md#停止再起動アップデート)にあります。

### オプション

| | |
|---|---|
| `--device NAME` | 中継するデバイス（`tailscale status` の名前）。複数は繰り返して指定 |
| `--allow-hosts` | 記録するホスト（その接続は復号する）。`api.example.com`、`*.example.com`、すべてなら `'*'`、`@FILE` |
| `--pass-hosts` | 許可したホストのうち、復号せずに通すもの。証明書ピンニングをするアプリ向け |
| `--rules FILE` | 許可したホストへのリクエストの行き先を書き換えるルール（`map_remote`、`map_local` など） |
| `--state DIR` | ノードキーと CA を置く状態ディレクトリ。デフォルトは `~/.reqcove` |

すべてのオプションは[ガイド](docs/guide.ja.md#オプション)にあります。

### ほかの使い方

- [エージェントに通信を読ませる](docs/guide.ja.md#エージェントに通信を読ませる)：Skill、ほかのデバイスのエージェント
- [自分でフローを見る](docs/guide.ja.md#自分でフローを見る)：iPhone で、HAR ファイルで、mitmweb で
- [iPhone アプリ以外のクライアントを記録する](docs/guide.ja.md#iphone-アプリ以外のクライアントを記録する)：証明書ピンニングをするアプリ、Android、iOS シミュレーター、Web アプリのバックエンド
- [リクエストの行き先を変える](docs/guide.ja.md#リクエストの行き先を変える)：開発サーバーへ送る、別のプロキシに回す
- [1 台で複数の Exit Node](docs/several-exit-nodes.ja.md)、[コンテナ](docs/container.ja.md)、[別の Mac をデバイスに](docs/another-mac.ja.md)

## セキュリティ

- 記録するのは、`--allow-hosts` のホストへのリクエストだけです。ただし、許可したホストの接続に、ほかのホストへのリクエストが相乗りすることがあり（HTTP/2 の接続の再利用）、それも復号されます。記録はしませんが、`--web` では表示され、`--upstream-proxy` に転送されることがあります。Apple のホストへの接続は、常に復号せずに通します。
- Reqcove が見分けられるシークレット（トークン、鍵、Cookie、パスワード）は、届いた時点でマスクします。**ボディの中にあって、名前からシークレットと分からないものは見つけられません。** メールアドレスなどの個人情報もマスクしません。
- エージェントが読んだものは、そのモデルの提供元に送られます。ボディは外部のサイトが書いたもので、エージェントに指示しようとすることがあります。
- Exit Node は、このコンピュータ、LAN、tailnet を宛先として拒否します。

詳しくは [docs/SECURITY.md](docs/SECURITY.md) を見てください（英語）。

## 制限事項

- 証明書ピンニングをするアプリは、Reqcove の証明書を拒否します。[`--pass-hosts`](docs/guide.ja.md#証明書ピンニングをするアプリを通す--pass-hosts) を見てください。
- mitmproxy を通るのは TCP の 80 番と 443 番ポートだけです。ほかのポートはそのまま中継します。
- IPv6 は拒否し、QUIC は（Apple 宛て以外）ドロップします。アプリは IPv4 と TCP にフォールバックします。
- iPhone から、このコンピュータや LAN には直接届きません。許可したホストへのリクエストを、ルールでそこへ送ることはできます。
- iPhone が使用中に reqcove が停止すると、iPhone の DNS が止まったままになることがあります（[tailscale#20870](https://github.com/tailscale/tailscale/issues/20870)）。Exit Node を一度オフにして、オンに戻してください。
- コンピュータはスリープさせないでください。`reqcove run` は macOS のアイドルスリープを防ぎますが、蓋を閉じたときのスリープは防げません。

ほかの制限事項は[ガイド](docs/guide.ja.md#制限事項)にあります。

## ライセンス

MIT。Reqcove は Tailscale の fork（BSD-3-Clause）とそのほかのオープンソースモジュールを使っています。リリースのアーカイブにはそれらのライセンスを同梱しています。
