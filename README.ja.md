# Reqcove

[![test](https://github.com/mh-mobile/reqcove/actions/workflows/test.yml/badge.svg)](https://github.com/mh-mobile/reqcove/actions/workflows/test.yml)
[![release](https://img.shields.io/github/v/release/mh-mobile/reqcove)](https://github.com/mh-mobile/reqcove/releases)
[![license](https://img.shields.io/github/license/mh-mobile/reqcove)](LICENSE)

iPhone の HTTP(S) 通信を、iPhone が手元にあっても離れた場所にあっても、AI エージェントに渡すツールです。

Reqcove（レクコーブ）という名称は、request（リクエスト）と cove（入り江）を組み合わせた造語です。リクエストが集まる入り江、というイメージです。

[English](README.md)

iPhone はあなたのコンピュータを Tailscale の **Exit Node** として選びます。そのコンピュータ上で動く Reqcove（単一のバイナリ）が通信を中継し、許可したホストの通信を [mitmproxy](https://mitmproxy.org) で復号して、フローを [MCP](https://modelcontextprotocol.io) でエージェントに提供します。iPhone 側で必要な設定は Exit Node を選ぶことと、CA を一度信頼することだけです。Wi-Fi でも 5G でも使えます。

```text
iPhone ──(tailnet, Exit Node)──▶ reqcove run ──SOCKS5──▶ mitmproxy ──▶ インターネット
                                     │                       │
                                     │                アドオン: フロー
                                     ▼                       ▼
                              agent ◀── MCP ── reqcove mcp ◀─ 記録（マスク済み）
```

Reqcove は RoamRun とは別のツールです。RoamRun は遠くにあるデバイスを Xcode につなぐためのもので、通信は読みません。

> **開発状況：初期段階です**（v0.7）。macOS（Apple シリコン）と Ubuntu 24.04（arm64）で、iPhone を使って試しました。試していないことは、ドキュメントにその旨を書いています。

## 必要なもの

- Apple シリコンの macOS、または Linux（amd64 または arm64）
- [uv](https://docs.astral.sh/uv/)。初回起動時に、Reqcove が uv を使って mitmproxy（12.3.1）と Python を取得します。ほかにインストールするものはありません
- Tailscale の tailnet と、iPhone にインストールした Tailscale アプリ

## インストール

Homebrew で入れます（macOS と Linux。ソースからビルドし、uv も一緒に入ります）。

```sh
brew trust --formula mh-mobile/tap/reqcove   # Homebrew 7 は、公式以外の tap の formula を信頼してから読み込む
brew install mh-mobile/tap/reqcove
```

[Releases](https://github.com/mh-mobile/reqcove/releases) からバイナリをダウンロードして使うこともできます（Apple シリコンの macOS、Linux の amd64 と arm64）。その場合、uv は自分で入れてください。macOS のバイナリは Developer ID で署名してあり、Apple の公証（notarization）を受けています。ブラウザでダウンロードしたものも、そのまま動きます。

ソースからビルドすることもできます（Go 1.27）。

```sh
git clone https://github.com/mh-mobile/reqcove && cd reqcove
go build -o reqcove ./cmd/reqcove
```

できた `reqcove` は `PATH` の通ったディレクトリに置いてください（または `./reqcove` として実行します）。

`go install …@version` は使えません。Reqcove は Tailscale の tsnet の fork を `replace` ディレクティブで使っているためです。

## 使い方

初めてのときは、ターミナルで次を実行します。

```sh
reqcove setup
```

uv があるかを確かめ、tailnet での iPhone の名前と記録するホストを聞いて、`~/.config/reqcove/config` に書きます。Homebrew で入れた場合は Homebrew の `etc/reqcove/config` に書きます（ファイルがすでにあれば表示し、`y` と答えない限りそのまま残します。置き換えるときは、元のファイルを `config.old` として残します）。`y` と答えればエージェントの Skill を入れ、Claude Code にツールを渡すコマンドを表示します。setup 自身は何も起動しません。そのあとは次のとおりです。

- setup が示すとおりに起動します。`brew services start reqcove`（Homebrew で入れた場合）、`reqcove service install`、またはターミナルで `reqcove run --config FILE` です。
- `reqcove links` がログイン用の URL（初回）と CA の QR コードを表示します。Exit Node の承認など、残っていることは `reqcove status` で確認できます。
- そのあと、下の手順 2 と 3 を iPhone で行います。

手で行う場合は次のとおりです。

1. コンピュータ側で起動します。中継する iPhone（`tailscale status` に表示される名前）と、記録するホストを指定します。

   ```sh
   reqcove run --device iphone --allow-hosts 'api.example.com,*.example-cdn.com'
   ```

   初回はターミナルにログイン用の URL が表示され（`reqcove links` でもう一度表示できます）、続けてほかに必要なこと（Exit Node の承認、Tailnet Lock）が表示されます。不足しているものは `reqcove status` でいつでも確認できます。
2. iPhone の Tailscale アプリで、Exit Node に `reqcove` を選びます。
3. 同じく iPhone で、Reqcove の CA を信頼します。`reqcove run` が表示する QR コード（サービスとして起動した場合などは `reqcove links` でも表示できます）をカメラで読むか、Safari で `http://mitm.it` を `http://` から入力して開きます。「設定 › プロファイルがダウンロード済み」でプロファイルをインストールし、「設定 › 一般 › 情報 › 証明書信頼設定」で信頼します（名前は `Reqcove CA (<コンピュータ名>, <日付>)`）。
4. エージェントに、MCP ツールと、その使い方を教える Skill を入れます。Claude Code の場合は次のとおりです。

   ```sh
   claude mcp add reqcove -- reqcove mcp
   reqcove init
   ```

   あとは「この 10 分間で api.example.com へのリクエストのうち、失敗したものは？」のように聞いてみてください。

エージェントは `summarize`、`list_flows`、`search_flows`、`get_flow` などの MCP ツールで記録を読みます（[ツールの一覧](docs/guide.ja.md#mcp-ツール)）。RoamRun などで iPhone を操作したあとは、その操作で送られたリクエストを `wait_for_flows` で待って受け取れます。`--rules` のファイルでプリセットにしたルールがあれば、そのルールを一度に数分ずつ有効にすることもできます（`activate_preset`、[プリセット](docs/guide.ja.md#エージェントが有効にできるプリセット)）。エラーをアプリがどう扱うかを見るためのモックや、v0.7 からは、アプリをステージングのサーバーへ向ける `map_remote` や `resolve` のルールです。ツールでルールを書いたり変えたりはできません（ファイルを書けるエージェントがルールを書くのは、あなたが頼んだときだけです）。`reqcove cleanup` はすべてを元に戻す手順を表示します。停止・再起動・アップデートは[ガイド](docs/guide.ja.md#停止再起動アップデート)にあります。

### オプション

| | |
|---|---|
| `--device NAME` | 中継するデバイス（`tailscale status` の名前）。複数は繰り返して指定 |
| `--allow-hosts` | 記録するホスト（その接続は復号する）。`api.example.com`、`*.example.com`、すべてなら `'*'`、`@FILE` |
| `--pass-hosts` | 許可したホストのうち、復号せずに通すもの。証明書ピンニングをするアプリ向け |
| `--rules FILE` | 許可したホストへのリクエストの行き先を書き換えるルール（`map_remote`、`map_local` など）や、ここで応答を返すルール（`mock`） |
| `--state DIR` | ノードキーと CA を置く状態ディレクトリ。デフォルトは `~/.reqcove` |

すべてのオプションは[ガイド](docs/guide.ja.md#オプション)にあります。

### ほかの使い方

- [エージェントに通信を読ませる](docs/guide.ja.md#エージェントに通信を読ませる)：Skill、ほかのデバイスのエージェント
- [自分でフローを見る](docs/guide.ja.md#自分でフローを見る)：iPhone で、HAR ファイルで、mitmweb で
- [iPhone アプリ以外のクライアントを記録する](docs/guide.ja.md#iphone-アプリ以外のクライアントを記録する)：証明書ピンニングをするアプリ、Android、iOS シミュレーター、Web アプリのバックエンド
- [リクエストの行き先を変える](docs/guide.ja.md#リクエストの行き先を変える)：開発サーバーへ送る、別のプロキシに回す
- [サービスとして動かす](docs/guide.ja.md#サービスとして動かす)、[うまくいかないとき](docs/guide.ja.md#うまくいかないとき)
- [1 台で複数の Exit Node](docs/several-exit-nodes.ja.md)、[コンテナ](docs/container.ja.md)、[別の Mac をデバイスに](docs/another-mac.ja.md)
- [互換性](docs/COMPATIBILITY.ja.md)：v1.0.0 から変わらないものと、変わるときの知らせ方

### Tailscale を使わずに（LAN モード）

同じネットワークなら、Tailscale なしで、iPhone がこのコンピュータを Wi-Fi のプロキシとして使うこともできます。`reqcove run --lan --allow-hosts api.example.com` を実行し、iPhone の Wi-Fi のプロキシ設定（手動）に `run` が表示するアドレスとポートを入力して、このコンピュータで iPhone のアドレスを許可します（`run` が質問するか、`reqcove lan allow ADDR`）。続いて、デバイスごとに 1 回、CA を信頼します。プロキシを設定した状態で `http://mitm.it` を開くか、`run` が表示する CA のファイルを AirDrop で送り（AirDrop は未確認）、`run` が表示する SHA-256 とプロファイルの「詳細」の値を照合します。インストールと信頼は上の手順 3 と同じです。Wi-Fi のみ、80 番と 443 番ポートのみで、パスワードはありません。許可したアドレスはこのコンピュータを通して通信できます。自宅の Wi-Fi の iPhone（iOS 27.3）で試しました。届く先とつながらない原因は[ガイド](docs/guide.ja.md#tailscale-を使わずに同じネットワークでつなぐ--lan)にあります。

## セキュリティ

- 記録するのは `--allow-hosts` のホストへのリクエストだけです。ただし、許可したホストの接続に、ほかのホストへのリクエストが相乗りすることがあり（HTTP/2 の接続の再利用）、それも復号されます。記録はしませんが、`--web` では表示され、`--upstream-proxy` に転送されることがあります。Apple のホストへの接続は常に復号せずに通します。
- Reqcove が見分けられるシークレット（トークン、鍵、Cookie、パスワード）は、届いた時点でマスクします。**ボディの中にあって、名前からシークレットと分からないものは見つけられません**（`--mask-names` や `--mask-values` で足せます）。メールアドレスなどの個人情報もマスクしません。
- エージェントが読んだものは、そのモデルの提供元に送られます。ボディは外部のサイトが書いたもので、サイトがその中でエージェントに指示しようとすることがあります。
- Exit Node はこのコンピュータ、LAN、tailnet を宛先として拒否します。
- LAN モード（`--lan`）にはパスワードがありません。このコンピュータで許可したアドレスは、このコンピュータを通って、あなたのアドレスからインターネット（80 番と 443 番ポート）と、`--allow-hosts` に完全な名前で書いたプライベートなホストに届きます。

詳しくは [docs/SECURITY.ja.md](docs/SECURITY.ja.md) を見てください。

## 制限事項

- 証明書ピンニングをするアプリは、Reqcove の証明書を拒否します。[`--pass-hosts`](docs/guide.ja.md#証明書ピンニングをするアプリを通す--pass-hosts) を見てください。
- mitmproxy を通るのは TCP の 80 番と 443 番ポートだけです。ほかのポートはそのまま中継します。
- IPv6 は拒否し、QUIC は（Apple 宛て以外）ドロップします。アプリは IPv4 と TCP にフォールバックします。
- iPhone から、このコンピュータや LAN には直接届きません。許可したホストへのリクエストを、ルールでそこへ送ることはできます。
- iPhone が使っている間に reqcove が停止すると、iPhone の DNS が止まったままになることがあります（[tailscale#20870](https://github.com/tailscale/tailscale/issues/20870)）。Exit Node を一度オフにして、オンに戻してください。
- コンピュータはスリープさせないでください。`reqcove run` は macOS のアイドルスリープを防ぎますが、蓋を閉じたときのスリープは防げません。

ほかの制限事項は[ガイド](docs/guide.ja.md#制限事項)にあります。

## ライセンス

MIT。Reqcove は Tailscale の fork（BSD-3-Clause）とそのほかのオープンソースモジュールを使っています。リリースのアーカイブにはそれらのライセンスを同梱しています。
