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

> **開発状況：v1.0 です。** MCP のツール、CLI、ルールのファイルは、v2 まで互換性を保ちます（[COMPATIBILITY](docs/COMPATIBILITY.ja.md)）。今のところ試したのは作者だけで、macOS（Apple シリコン）と Ubuntu 24.04（arm64）で、iPhone を使って試しました。試していないことは、ドキュメントにその旨を書いています。

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

初回の手順は 4 つです。コンピュータで 1 つ、iPhone で 2 つ、エージェントに 1 つあります。

1. **コンピュータで設定して起動します。** ターミナルで次を実行します。

   ```sh
   reqcove setup
   ```

   setup は uv があるかを確かめ、tailnet での iPhone の名前（`tailscale status` に表示される名前）と記録するホストを聞いて、設定ファイルに書きます。ファイルは `~/.config/reqcove/config` で、Homebrew で入れた場合は Homebrew の `etc/reqcove/config` です。`y` と答えるとエージェントの Skill も入れ、Claude Code にツールを渡すコマンドを表示します。setup 自身は何も起動しません（[聞くことと書くもの](docs/guide.ja.md#初回の起動ログインと承認)）。

   続いて、setup が示す方法で起動します。`brew services start reqcove`（Homebrew で入れた場合）、`reqcove service install`、ターミナルでの `reqcove run --config FILE` のどれかです。

   初回はログインが必要です。ログイン用の URL は `reqcove links` で表示できます。Exit Node の承認など、残っている手順は `reqcove status` で確認できます。
2. **iPhone で Exit Node を選びます。** Tailscale アプリで、Exit Node に `reqcove` を選びます。
3. **iPhone で Reqcove の CA を信頼します。** CA の QR コードをカメラで読み取ります。QR コードは `reqcove links` が表示し、ターミナルで起動した `reqcove run` も表示します。Safari で `http://mitm.it` を開く方法もあります（`http://` から入力します）。続いて「設定 › プロファイルがダウンロード済み」でプロファイルをインストールし、「設定 › 一般 › 情報 › 証明書信頼設定」で信頼します。CA の名前は `Reqcove CA (<コンピュータ名>, <日付>)` です。
4. **エージェントにツールを渡します。** ツールの使い方を教える Skill も入れます。Claude Code の場合は次のとおりです。

   ```sh
   claude mcp add reqcove -- reqcove mcp
   reqcove init
   ```

   1 行目は setup が表示したコマンドです。`reqcove init` は Skill を入れます。setup で `y` と答えていれば、Skill はもう入っています。

   あとは「この 10 分間で api.example.com へのリクエストのうち、失敗したものは？」のように聞いてみてください。

setup を使わない場合は、手順 1 をターミナルのコマンド 1 つで行います。中継する iPhone（`tailscale status` に表示される名前）と、記録するホストを指定します。

```sh
reqcove run --device iphone --allow-hosts 'api.example.com,*.example-cdn.com'
```

初回はターミナルにログイン用の URL が表示されます（`reqcove links` でもう一度表示できます）。続けて、ほかに必要なこと（Exit Node の承認、Tailnet Lock）が表示されます。不足しているものは `reqcove status` でいつでも確認できます。手順 2 から 4 は同じです。

### エージェントにできること

- `summarize`、`list_flows`、`search_flows`、`get_flow` などの MCP ツールで記録を読みます（[ツールの一覧](docs/guide.ja.md#mcp-ツール)）。
- RoamRun などで iPhone を操作したあとは、その操作で送られたリクエストを `wait_for_flows` で待って受け取れます。
- `--rules` のファイルでプリセットにしたルールがあれば、そのルールを一度に数分ずつ有効にすることもできます（`activate_preset`、[プリセット](docs/guide.ja.md#エージェントが有効にできるプリセット)）。エラーをアプリがどう扱うかを見るためのモックや、アプリをステージングのサーバーへ向ける `map_remote` や `resolve` のルールです。
- ツールでルールを書いたり変えたりはできません（ファイルを書けるエージェントがルールを書くのは、あなたが頼んだときだけです）。

すべてを元に戻す手順は `reqcove cleanup` が表示します。停止・再起動・アップデートは[ガイド](docs/guide.ja.md#停止再起動アップデート)にあります。

### オプション

主なオプションです。すべてのオプションは[ガイド](docs/guide.ja.md#オプション)にあります。

| | |
|---|---|
| `--device NAME` | 中継するデバイス（`tailscale status` の名前）。複数は繰り返して指定 |
| `--allow-hosts` | 記録するホスト（その接続は復号する）。`api.example.com`、`*.example.com`、すべてなら `'*'`、`@FILE` |
| `--pass-hosts` | 許可したホストのうち、復号せずに通すもの。証明書ピンニングをするアプリ向け |
| `--rules FILE` | 許可したホストへのリクエストの行き先を書き換えるルール（`map_remote`、`map_local` など）や、ここで応答を返すルール（`mock`） |
| `--state DIR` | ノードキーと CA を置く状態ディレクトリ。デフォルトは `~/.reqcove` |

### ほかの使い方

- [エージェントに通信を読ませる](docs/guide.ja.md#エージェントに通信を読ませる)：Skill、ほかのデバイスのエージェント
- [自分でフローを見る](docs/guide.ja.md#自分でフローを見る)：iPhone で、HAR ファイルで、mitmweb で
- [iPhone アプリ以外のクライアントを記録する](docs/guide.ja.md#iphone-アプリ以外のクライアントを記録する)：証明書ピンニングをするアプリ、Android、iOS シミュレーター、Web アプリのバックエンド
- [リクエストの行き先を変える](docs/guide.ja.md#リクエストの行き先を変える)：開発サーバーへ送る、別のプロキシに回す
- [サービスとして動かす](docs/guide.ja.md#サービスとして動かす)、[うまくいかないとき](docs/guide.ja.md#うまくいかないとき)
- [1 台で複数の Exit Node](docs/several-exit-nodes.ja.md)、[コンテナ](docs/container.ja.md)、[別の Mac をデバイスに](docs/another-mac.ja.md)
- [互換性](docs/COMPATIBILITY.ja.md)：v1.0.0 から変わらないものと、変わるときの知らせ方

### Tailscale を使わずに（LAN モード）

同じネットワークなら、Tailscale なしで、iPhone がこのコンピュータを Wi-Fi のプロキシとして使うこともできます。

```sh
reqcove run --lan --allow-hosts api.example.com
```

Wi-Fi のみ、80 番と 443 番ポートのみで、パスワードはありません。このコンピュータで許可したアドレスは、このコンピュータを通して通信できます。手順（iPhone のプロキシ設定、アドレスの許可、CA の信頼）、届く先、つながらない原因は[ガイド](docs/guide.ja.md#tailscale-を使わずに同じネットワークでつなぐ--lan)にあります。自宅の Wi-Fi の iPhone（iOS 27.3）で試しました。

## セキュリティ

- 記録するのは `--allow-hosts` のホストへのリクエストだけです。Apple のホストへの接続は常に復号せずに通します。
- 許可したホストの接続に、ほかのホストへのリクエストが相乗りすることがあります（HTTP/2 の接続の再利用）。このリクエストも復号されます。記録はしませんが、`--web` では表示され、`--upstream-proxy` に転送されることがあります。
- Reqcove が見分けられるシークレット（トークン、鍵、Cookie、パスワード）は、届いた時点でマスクします。**ボディの中にあって、名前からシークレットと分からないものは見つけられません**（`--mask-names` や `--mask-values` で足せます）。メールアドレスなどの個人情報もマスクしません。
- エージェントが読んだものは、そのモデルの提供元に送られます。ボディは外部のサイトが書いたもので、サイトがその中でエージェントに指示しようとすることがあります。
- Exit Node はこのコンピュータ、LAN、tailnet を宛先として拒否します。
- LAN モード（`--lan`）にはパスワードがありません。このコンピュータで許可したアドレスは、このコンピュータを通って、あなたのアドレスからインターネット（80 番と 443 番ポート）と、`--allow-hosts` に完全な名前で書いたプライベートなホストに届きます。

詳しくは [docs/SECURITY.ja.md](docs/SECURITY.ja.md) を見てください。

## 制限事項

- 証明書ピンニングをするアプリは、Reqcove の証明書を拒否します。[`--pass-hosts`](docs/guide.ja.md#証明書ピンニングをするアプリを通す--pass-hosts) を見てください。
- mitmproxy を通るのは TCP の 80 番と 443 番ポートだけです。ほかのポートはそのまま中継します。
- 許可したホストへの接続のうち、mitmproxy が HTTP として読まないもの（ほかのプロトコル、知らない ALPN の接続の一部、`101` でアップグレードした先）は、接続としてだけ記録します。その接続が運ぶものはフローになりません。[raw TCP](docs/guide.ja.md#http-として読まれない接続raw-tcp) を見てください。
- IPv6 は拒否し、QUIC は（Apple 宛て以外）ドロップします。アプリは IPv4 と TCP にフォールバックします。
- iPhone から、このコンピュータや LAN には直接届きません。許可したホストへのリクエストを、ルールでそこへ送ることはできます。
- iPhone が使っている間に reqcove が停止すると、iPhone の DNS が止まったままになることがあります（[tailscale#20870](https://github.com/tailscale/tailscale/issues/20870)）。Exit Node を一度オフにして、オンに戻してください。
- コンピュータはスリープさせないでください。`reqcove run` は macOS のアイドルスリープを防ぎますが、蓋を閉じたときのスリープは防げません。

ほかの制限事項は[ガイド](docs/guide.ja.md#制限事項)にあります。

## ライセンス

MIT。Reqcove は Tailscale の fork（BSD-3-Clause）とそのほかのオープンソースモジュールを使っています。リリースのアーカイブにはそれらのライセンスを同梱しています。
