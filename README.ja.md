# Reqcove

[![test](https://github.com/mh-mobile/reqcove/actions/workflows/test.yml/badge.svg)](https://github.com/mh-mobile/reqcove/actions/workflows/test.yml)
[![release](https://img.shields.io/github/v/release/mh-mobile/reqcove)](https://github.com/mh-mobile/reqcove/releases)
[![license](https://img.shields.io/github/license/mh-mobile/reqcove)](LICENSE)

手元の iPhone でも、遠くにある iPhone でも、その HTTP(S) 通信を AI エージェントに渡します。

[English](README.md)

iPhone は、あなたのコンピュータを Tailscale の **Exit Node** として選びます。そのコンピュータ上で動く Reqcove（単一のバイナリ）が通信を中継し、許可したホストの通信を [mitmproxy](https://mitmproxy.org) で復号して、フローを [MCP](https://modelcontextprotocol.io) でエージェントに提供します。iPhone 側で必要な設定は、Exit Node を選ぶことと、CA を一度信頼することだけです。Wi-Fi でも 5G でも使えます。

```
iPhone ──(tailnet, Exit Node)──▶ reqcove run ──SOCKS5──▶ mitmproxy ──▶ インターネット
                                     │                       │
                                     │                アドオン: フロー
                                     ▼                       ▼
                              agent ◀── MCP ── reqcove mcp ◀─ 記録（マスク済み）
```

Reqcove は RoamRun とは別のツールです。RoamRun は遠くにあるデバイスを Xcode につなぐためのもので、通信は読みません。

> **開発状況：初期段階です**（v0.1）。以下の内容はすべて、macOS（Apple シリコン）と Ubuntu 24.04（arm64）で、iPhone を使って試したものです。試していないことは、その旨を明記しています。

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
   reqcove run --device iphone --allow-hosts 'api.example.com,*.example.com'
   ```

   初回はログイン用の URL が表示されます。Tailnet Lock を使っている場合は、続けて、署名用のデバイスで実行する `tailscale lock sign nodekey:…` が表示され、管理コンソールで Exit Node を承認するよう案内されます。不足しているものは `reqcove status` でいつでも確認できます。
2. iPhone の Tailscale アプリで、Exit Node に `reqcove` を選びます。
3. 同じく iPhone で、Exit Node をオンにしたまま、`reqcove run` が表示する QR コードをカメラで読みます（または Safari で `http://mitm.it` を開きます。`http://` まで自分で入力してください。省略すると Safari が HTTPS で開こうとして警告を出すことがあります）。そして、iOS のプロファイルをインストールして（設定 › プロファイルがダウンロード済み）、設定 › 一般 › 情報 › 証明書信頼設定 で信頼します。CA の名前は `Reqcove CA (<コンピュータ名>, <日付>)` です。
4. エージェントに MCP ツールを登録します。Claude Code の場合：

   ```sh
   claude mcp add reqcove -- reqcove mcp
   ```

   あとは「この 10 分間で api.example.com へのリクエストのうち、失敗したものは？」のように聞いてみてください。

Exit Node の代わりに、iPhone の Wi-Fi のプロキシ設定（手動）に、reqcove ノードの tailnet アドレスとポート 8080（`--proxy-port`）を指定する方法もあります。モバイル通信にはプロキシ設定がないため、こちらは Wi-Fi でのみ使えます。

### MCP ツール

| ツール | |
|---|---|
| `list_flows` | フローを新しい順に一覧します。デバイス、ホスト（サブドメインを含む）、時間（`since: "10m"`）、ステータスコード（`404`、`4xx`、`none`）、メソッドで絞り込めます。ページング対応 |
| `search_flows` | URL とヘッダーのテキストを検索します（`bodies` を指定するとボディの先頭も対象） |
| `get_flow` | フローを 1 件取得します。ボディは `bodies` を指定したときだけ含まれます |
| `summarize` | ホスト、User-Agent、ステータスコード、メソッド、デバイス、Content-Type ごとの件数 |
| `list_devices` | 中継しているデバイスと、それぞれの件数、最終アクティビティ |
| `list_tls_failures` | デバイスが拒否した TLS ハンドシェイク。多くは証明書ピンニングか、まだ信頼されていない CA が原因です |
| `capture_stats` | mitmproxy の状態、記録がカバーしている期間、ドロップ数 |
| `status` | セットアップが完了しているか。未完了なら次の手順 |

### オプション

| | |
|---|---|
| `--device NAME` | 中継するデバイス。マシン名、デバイス名（自分のデバイスで、タグのないものに限る）、tailnet の IP アドレス、StableID のいずれか。複数指定するには繰り返します |
| `--allow-hosts` | 復号して記録するホスト。`api.example.com`、`*.example.com`、またはすべてを対象にする `'*'`。指定しない場合、通信は中継しますが何も記録しません |
| `--rules FILE` | 許可したホストにだけ効くルールを書いた YAML（下を参照） |
| `--rules-reload` | 動いている間、そのファイルが変わるたびに読み直します（下を参照。v0.1.0 のあとに追加） |
| `--upstream-proxy URL` | 復号したリクエストを、Burp Suite などの HTTP プロキシに回します。`http://127.0.0.1:8080` など（下を参照。v0.1.0 のあとに追加） |
| `--upstream-ca FILE` | そのプロキシの CA（PEM か DER）。自分で復号するプロキシのときに渡します。このコンピュータの Burp なら、自動で取ってきます |
| `--local-proxy` | このコンピュータ自身のアプリ（iOS シミュレーターなど）用の HTTP プロキシを `127.0.0.1:8082` に開きます（下を参照。v0.1.0 のあとに追加） |
| `--ui` | 記録を iPhone 自身で見る、読むだけのページを、ノードの 80 番で出します（下を参照。v0.1.0 のあとに追加） |
| `--web` | 代わりに mitmweb を `http://127.0.0.1:8081` で起動します（マスクなし。編集とリプレイができ、すべてのフローを保持します）。v0.1.0 のあとは、tailnet の自分の端末からも、ノードの 8081 番で開けます（`run` が出すリンクか QR コードで。ほかの端末からはまだ試していません。テストは mitmweb の代わりのプログラムで確かめています） |
| `--dns` | Exit Node が使う上流 DNS（カンマ区切り）。デフォルトは `1.1.1.1:53`（ポートは省けます。v0.1.0 のあとに追加）。`system` を指定すると `/etc/resolv.conf` の最初の nameserver を使います |
| `--no-redact` | シークレットをマスクせずに記録します |
| `--state DIR` | 状態ディレクトリ。デフォルトは `~/.reqcove`。ノードキー、CA とその秘密鍵が入ります。新しいか空のディレクトリ、または reqcove が前に使ったものに限ります |

### ルール

```yaml
map_remote:                     # mitmproxy の書式（map_local、modify_headers も同じ）
  - "|https://api.example.com/|http://localhost:3000/"
keep_host_header: true          # Reqcove 独自：map_remote でもアプリの Host を残す
resolve:                        # Reqcove 独自：Host と SNI はそのままで、つなぐ先だけ変える
  - "shop.example.com=203.0.113.10"
  - "auth.example.com=192.168.1.20:8443"
```

- `map_remote`、`map_local`、`modify_headers` は mitmproxy の書式で、mitmproxy 自身のコードが処理します。相対パスは、ルールのファイルがある場所から数えます。
- `map_remote` は URL を書き換えるので、`Host` ヘッダーも変わります。`keep_host_header` を true にすると、`Host` はアプリが送ったままになります。このコンピュータの開発サーバー（`http://localhost:3000` など）につなぐなら、こちらを使います。アプリは `https` で送るので、上の例のようにスキームも書き換えてください（平文のサーバーは TLS に答えられません）。
- `resolve` は、その名前へのリクエストを、書いた IPv4 アドレスへ送ります。このコンピュータや LAN のアドレスも使えます。`Host`、SNI、記録される URL は変わらず、TLS もその名前で確かめます。そのため、向け先のサーバーには、その名前の証明書が必要です（ステージングや新しいロードバランサーなど）。証明書のない手元の HTTPS サーバーでは 502 になります。
  - `map_remote` が効いたときは、書き換えたあとの URL のホスト名で照らし、それが SNI にもなります。
  - ポートを書かないと、リクエストのポート（アプリがつないだ 80 番か 443 番、または `map_remote` の URL のポート）を使います。平文の HTTP は、証明書で確かめられません。
  - 名前は今までどおり引かれ（Exit Node では iPhone が、Remote Proxy ではこのコンピュータが引きます）、まず本物のサーバーにつなぎます。そのため、公開の DNS で引けない名前や、本物のサーバーがつながらないときは、向け先を変えられません。
  - 名前は `--allow-hosts` に入っている必要があります。また、名前ごとに別のアドレス（かポート）にしてください。mitmproxy は、接続をアドレスで使い回すためです。
  - `0.0.0.0/8`、リンクローカル（クラウドのメタデータを含む）、マルチキャスト、Tailscale の 100.100.100.100 は拒みます。
- 他人が作ったルールのファイルは、中身を読んでから使ってください。ルールは、アプリのリクエストを Cookie やトークンごと、書かれた先へ送れます。
- ファイルは mitmproxy が起動するときに読みます（`run` の起動のときと、落ちた mitmproxy を reqcove が起動し直すとき）。`--rules-reload`（v0.1.0 のあとに追加）を付けると、書き換えが落ち着いてから、2 秒ほどで（コードからの見積もり）読み直し、そのあとに始まるリクエストから効きます。途中のリクエストは、始まったときのルールのままです。読めないファイルにしたときは、前のルールのまま動き、`run` と `reqcove status` が理由を出します。ただし、その間に mitmproxy が起動し直すと、起動のときと同じく `run` が止まります。これを付けると、ファイルを書けるもの（エージェントを含む）が、起動し直さずに、デバイスのリクエストの行き先を変えられます。

### 記録を iPhone で見る（`--ui`）

> v0.1.0 にはありません。次のリリースまでは、ソースからビルドして使ってください。

`reqcove run --ui` は、tailnet のノードに、記録を見るための読むだけのページを出し、そのリンクを QR コードで表示します。iPhone のカメラで読むと、Safari で一覧が開きます。一覧は 1 秒ごとに新しい記録を追います（「pause」で止まります）。Split View で、アプリと並べても使えます。記録を押すと、ヘッダーと本文が見られます（MCP の道具と同じく、マスク済みです）。iPhone のカメラから開けることは試しました。ページを読み込み直さずに新しい記録を追う動きと、ほかの端末から開くことは、まだ試していません。

- tailnet にある自分の端末（自分のアカウントでログインしている iPhone、サブ機の MacBook、iPad など）なら開けて、全端末の記録が見えます。`--device` に入れた他人の端末は、その端末自身の記録だけです。それ以外の端末は入れません。読めるのは、リンク（起動のたびに変わるトークン付き）を開いたブラウザだけです。
- Tailscale はオンにしておく必要があります。Exit Node でも Remote Proxy でも、どちらも使っていなくても開けます。このページを見る通信は、記録されません。

### iOS シミュレーター（`--local-proxy`）

> v0.1.0 にはありません。次のリリースまでは、ソースからビルドして使ってください。

```sh
reqcove run --allow-hosts api.example.com --local-proxy   # iPhone も記録するなら --device も
```

シミュレーターのアプリは、このコンピュータのネットワークを使うので、Exit Node では運べません。`--local-proxy` を付けると、代わりに `127.0.0.1:8082` に HTTP プロキシを開き、そこを通ったリクエストを `local` という端末として記録します。macOS では、Charles や Proxyman と同じように、`run` がシステムの Web プロキシ（HTTP と HTTPS、有効なネットワークサービスすべて）をそこへ向け、止まるときに元へ戻します。異常終了したときは、次の起動か `reqcove cleanup` で戻ります。起動しているシミュレーターには、Reqcove の CA も入れます（`xcrun simctl keychain … add-root-cert`）。あとから起動したシミュレーターには、表示されるコマンドで入れてください。Linux では何も書き換えません。アプリをプロキシに向け（`HTTPS_PROXY=http://127.0.0.1:8082`）、CA を信頼させてください。

- シミュレーターだけでなく、このコンピュータのアプリ全部が、このプロキシを通るようになります。復号して記録するのは `--allow-hosts` のホストだけですが、そのホストは、Reqcove の CA を信頼していないこのコンピュータのアプリ（Mac の Safari など）では、つながらなくなります。
- Exit Node と違い、このコンピュータや LAN を宛先として断りません。頼んでくるのが、もともとそこへ届くこのコンピュータ自身のアプリだからです。
- 本物の `networksetup` とシミュレーターでは、まだ試していません（テストは代わりのプログラムで確かめています）。

### HAR ファイルに書き出す

> v0.1.0 にはありません。次のリリースまでは、ソースからビルドして使ってください。

`reqcove run` が動いている間に `reqcove har > flows.har` を実行すると、記録を HAR 1.2 のファイルに、古い順で書き出します。デフォルトは新しい 1000 件までです（`--limit 0` で全部）。`--host`、`--device`、`--since 10m`、`--until`、`--status 4xx`、`--method` で絞り込めます。中身は MCP の道具が返すものと同じです。受け取った時点でマスク済みで、本文は先頭だけです（切れた本文は、コメントにそう書きます）。マスクで確かめられなかった本文は入りません。`run --no-redact` のときは何もマスクされず、ファイルのコメントにそう書きます。HAR 1.2 の仕様の必須の項目に沿って書いています（仕様を読んで書いたもので、検証ツールにはかけていません）が、ほかのツール（ブラウザの開発者ツール、Charles、Proxyman）で開くのは、まだ試していません。

### 上流のプロキシ（Burp Suite など）

> v0.1.0 にはありません。次のリリースまでは、ソースからビルドして使ってください。

Reqcove の記録を残したまま、同じリクエストを Burp Suite（や ZAP、Charles など）でも見るには、そちらに回します。

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' \
  --upstream-proxy http://127.0.0.1:8080
```

- 復号したリクエストは、プロキシを通ります（HTTPS は CONNECT のトンネルで、平文の HTTP はプロキシのリクエストとして）。本物のサーバーへ直接つなぐことはありません。`--allow-hosts` の外のホストへの接続は、今までどおり直接通ります。ただし、許可したホストへの復号した接続に相乗りした、ほかのホスト宛てのリクエスト（HTTP/2 の接続の使い回し）も、記録はしませんが、プロキシを通ります。Burp の Intercept はオフにしてください。オンだと、リクエストがそこで止まります。
- Reqcove は、iPhone がつないだアドレス（IP）をプロキシに渡します。ただ、Burp は HTTPS では、SNI の名前をこのコンピュータで引き直して、そちらにつなぎます（試して確かめました）。そのため、Exit Node が「このコンピュータと LAN は宛先にしない」と拒んでいても、Burp のつなぐ先には効きません。しかも、iPhone で開いたサイトが、その引き直しにこのコンピュータや LAN のアドレスを返すこともできます（DNS rebinding。コードを読んで考えたことで、試してはいません）。`--allow-hosts` は、試すホストだけにしてください（`'*'` のときは、`run` が警告を出します）。同じ理由で、`resolve` のルールは `--upstream-proxy` と一緒には使えません。プロキシ自身の設定（Burp の Hostname resolution overrides）を使ってください。平文の HTTP は、Burp では IP で表示され、名前は `Host` ヘッダーで分かります。
- プロキシを通る HTTPS は、プロキシの CA だけで確かめます。このコンピュータで動いていて、Burp のように `http://burp/cert` で CA を配るプロキシなら、起動のときに自動で取ってきます。ほかの、自分で復号するプロキシ（ZAP、Charles など）は、`--upstream-ca FILE`（PEM か DER）で CA を渡してください。どちらでもなければ、公開の CA で確かめます（自分では復号しないプロキシ向け）。
- プロキシを通るのは HTTP(S) だけです。許可したホストへの、ほかのプロトコル（MQTT など）は、本物のサーバーへ直接つながります（コードを読んで確かめたこと）。TLS の上のものは、プロキシの CA を使っているとき（`--upstream-ca` で渡したときも、Burp の CA を自動で取ってきたときも）、サーバーの証明書をその CA で確かめることになるので、失敗します。また、サーバーの名前（SNI）を送らない、IP アドレスへの HTTPS は、Burp を通すと失敗します。Burp が、そのアドレスを mitmproxy の受け付けない形で証明書に入れるためです。
- プロキシは、マスクしていない中身を全部見ます。Burp は、それをプロジェクトに残します。Burp Suite Community 2026.10 で試しました。ほかのプロキシは試していません。Burp で見えたこと：リクエストの本文は、全部届くまで Burp が溜めます。HTTP/1.1 のクライアントへの SSE（サーバーから流すイベント）は失敗します（iOS のアプリの多くが使う HTTP/2 なら流れます）。`--web` と一緒に使うと、mitmweb から平文の HTTP のリクエストを送り直したときに、プロキシ自身に送られます。

## セキュリティ

- 復号して記録するのは `--allow-hosts` に指定したホストだけです。同じ接続上のほかのホストへのリクエストは件数を数えるだけで、記録しません。Apple のホストは常に復号せずに通します。
- シークレットは受信した時点でマスクします。対象は、名前に authorization・token・secret・key・signature などの単語を含むヘッダーとクエリパラメータ（`accessToken` や `X-Amz-Signature` も含む）、Cookie の値、そして URL が出てくるところ（フラグメント、`Referer`・`Location` などのヘッダー、ボディ、エラーメッセージ）の同じパラメータと、URL に含まれるパスワードです。ボディでは、同じような名前の JSON とフォームの項目の値と、形で見分けられる認証情報（`Bearer …`、JWT、`ghp_…`・`sk-…`・`AKIA…` のようなキー）をマスクします。**名前からは分からない場所にある秘密は見つけられません。** メールアドレスなどの個人情報もマスクしません。テキストでないボディは確かめられないので、エージェントには渡しません。
- エージェントが読んだ内容は、そのモデルの提供元に送られます。ボディはリモートのサイトが書いたもので、エージェントに指示を与えようとすることがあります。ツールの説明にもその旨を書いています。
- mitmproxy の SOCKS5 ポートを使えるのは reqcove だけです（起動のたびに生成するパスワードで保護します）。MCP のソケットと状態ディレクトリは、自分の OS ユーザーだけがアクセスできます。
- Exit Node は、このコンピュータ自身、その LAN、tailnet を宛先とする通信を拒否します。
- ログは Tailscale に送りません。データプレーンの監査ログを必須とする tailnet には対応しておらず、`reqcove status` がその旨を表示します。

詳しくは [docs/SECURITY.md](docs/SECURITY.md)（英語）を参照してください。

## 制限事項

- 証明書ピンニングを行うアプリは復号できません（`list_tls_failures` に表示されます）。
- mitmproxy を通るのは TCP の 80 番と 443 番ポートだけです。ほかのポートはそのまま中継します。
- Exit Node は、このコンピュータと LAN を宛先として拒むので、iPhone からそこにある開発サーバーへは直接届きません。許可したホストへのリクエストを、ルールでそこへ送ることはできます（`map_remote` と `keep_host_header`。「ルール」を参照）。
- IPv6 は拒否します（アプリはすぐに IPv4 にフォールバックします）。QUIC は Apple 宛て以外をドロップするので、アプリは TCP にフォールバックします。見分けるのはアドレスで、ホストではありません。そのため、`--allow-hosts` に入っていないホストの QUIC も（`--allow-hosts` がないときも）TCP に切り替わります。443 以外のポートを使う QUIC は止めずにそのまま通し、記録もしません。
- Exit Node 経由の通話は試していません。
- Reqcove を動かしているコンピュータの iOS シミュレーターには、`--local-proxy` が要ります（上を参照。v0.1.0 のあとに追加）。別の Mac を `--device` に入れ、その Mac で Reqcove の Exit Node を使えば、シミュレーターの通信も、その Mac の通信と一緒に通るはずです。シミュレーターに Reqcove の CA を入れる必要があります（試していません）。
- mitmproxy は WebSocket のメッセージを、届ききるまで1つずつ溜めます。巨大なメッセージが来るとメモリを多く使います（mitmproxy が落ちたら、reqcove が起動し直します。起動し直しても 1 分以内に落ちるのが 5 回続くと、`run` が止まります）。
- `map_local` が答えるのは、ボディが 1 MiB 以下で長さが分かっているリクエストだけです。それ以外は本来の宛先へ送ります（記録にその旨が残ります）。長さのない HTTP/2 の GET には答えるので、そこにデバイスがボディを付けて送ってくると、まるごと溜めます。こうしたリクエストを送るのは、自分のデバイスだけです。
- iPhone が使用中に reqcove が停止すると、reqcove が復帰したあとも iPhone の DNS が止まったままになることがあります（[tailscale#20870](https://github.com/tailscale/tailscale/issues/20870)）。その場合は Exit Node を一度オフにして、オンに戻してください。
- コンピュータはスリープさせないでください。`reqcove run` は macOS のアイドルスリープを防ぎますが、蓋を閉じたときのスリープは防げません。

## Tips

- 新しいノードのたびに Exit Node を承認する手間を省くには、tailnet のポリシーに自動承認を追加します：`"autoApprovers": {"exitNode": ["you@example.com"]}`
- 状態ディレクトリが同じであれば、CA も同じままです。2 台のコンピュータで 1 つの CA を使うには、`~/.reqcove/mitmproxy/` をディレクトリごとコピーします（秘密鍵が含まれます）。
- `reqcove cleanup` は、すべてを元に戻す手順を表示します。`--delete-state` を付けると状態ディレクトリを削除します（reqcove が作ったものに限ります）。

## ライセンス

MIT。Reqcove は Tailscale の fork（BSD-3-Clause）とそのほかのオープンソースモジュールを使っています。リリースのアーカイブにはそれらのライセンスを同梱しています。
