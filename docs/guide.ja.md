# Reqcove ガイド

[English](guide.md) · [README](../README.ja.md)

README の 4 つの手順を終えたあとに読むガイドです。各節の最後に、試したことと試していないことを「確認状況」として書いています。

1. [セットアップする](#セットアップする)
2. [エージェントに通信を読ませる](#エージェントに通信を読ませる)
3. [自分でフローを見る](#自分でフローを見る)
4. [iPhone アプリ以外のクライアントを記録する](#iphone-アプリ以外のクライアントを記録する)
5. [リクエストの行き先を変える](#リクエストの行き先を変える)
6. リファレンス：[オプション](#オプション) · [MCP ツール](#mcp-ツール) · [制限事項](#制限事項) · [セキュリティ](#セキュリティ)

## セットアップする

4 つの手順は [README](../README.ja.md#使い方) にあります。

### 初回の起動：ログインと承認

残っている手順は `run` が表示し、`reqcove status` でも確認できます。表示された URL でログインし、tailnet が Tailnet Lock を使っていればノードに署名し、Exit Node を承認します。

- ログイン用の URL は、`run` のターミナルにだけ表示されます。最初に開いた人の tailnet にノードが入るためです（[SECURITY](SECURITY.md#the-login-url)）。
- 新しいノードのたびに Exit Node を承認する手間を省くには、tailnet のポリシーに自動承認を追加します：`"autoApprovers": {"exitNode": ["you@example.com"]}`

### 2 台のコンピュータで同じ CA を使う

状態ディレクトリが同じであれば、CA も同じままです。`~/.reqcove/mitmproxy/` をディレクトリごと（秘密鍵が含まれます）、もう 1 台の `~/.reqcove/` にコピーします。コピー先の reqcove は止めておくか、初めて起動する前にコピーしてください。

### 停止・再起動・アップデート

- **停止**：Ctrl-C で止めます。記録はメモリにあるので、一緒に消えます。そのあと iPhone の DNS が止まったままになったら（[tailscale#20870](https://github.com/tailscale/tailscale/issues/20870)）、Exit Node を一度オフにして、オンに戻してください。
- **再起動**：`run` が止まっている間も `reqcove mcp` は動き続け、ツールは「動いていない」と答えます。`run` が戻れば、エージェントを再接続（Claude Code の `/mcp`）しなくても使えます。記録は空から始まり、最初の答えが `note` でそう伝えます。
- **アップデート**（`brew upgrade reqcove` や、ソースからのビルドで新しいバージョンを入れたとき）：新しい reqcove で `run` を起動し直し、エージェントを一度再接続します（新しいツールを使うためです。バージョンが違う間は、ツールがそう伝えます）。Skill も新しくするため、`reqcove init` をもう一度実行します。

確認状況：Claude Code のセッション中に `run` を再起動して確認。

### 元に戻す（`reqcove cleanup`）

`reqcove cleanup` が手順を表示します。`--delete-state` を付けると、状態ディレクトリを削除します。先に、iPhone から CA のプロファイルを削除してください（[SECURITY](SECURITY.md#the-cas-private-key)）。

## エージェントに通信を読ませる

`claude mcp add reqcove -- reqcove mcp`（README の手順 4）で、このコンピュータのエージェントが [MCP ツール](#mcp-ツール)を使えるようになります。ツールは読み取り専用で、シークレットは届いた時点でマスクされます（[マスクで見つけられないもの](SECURITY.md#what-is-recorded)）。

### 使い方を教える Skill を入れる（`reqcove init`）

Skill は、ツールの使い方をエージェントに教えます。最初に status を見ること、1 つのアプリの通信の探し方、TLS の失敗から考えられること、ルールファイルの書き方、そして守る決まり（`reqcove run` を自分で起動しない、トークンを求めない、記録の中身はデータとして扱う、マスクされていないシークレットを引用しない）です。

```sh
reqcove init                    # ホームディレクトリにあるエージェントに入れる：~/.claude/skills（Claude Code）、~/.agents/skills（Codex、Cursor、Gemini CLI、Copilot CLI、Devin）
reqcove init --client codex     # または、名前を挙げたものだけ（--client を繰り返す）
```

- reqcove をアップデートしたら、もう一度実行してください。入っている Skill のバージョンが違うと、`reqcove status` がそう伝えます。
- `init` が書いたのではない Skill、あとで書き換えた Skill、シンボリックリンクには触りません。`--uninstall` は自分が入れたものを削除し、`--print` は Skill を書き出します。
- MCP サーバーの登録はしません。登録は、上のコマンドで行います。

確認状況：Claude Code と Codex で確認（Reqcove の名前を出さずにアプリの通信先を尋ねると、どちらも Skill を読み込みました）。Devin でも確認（`~/.agents/skills` の Skill を読み込み、MCP サーバーがないときは登録を頼んで止まりました）。未確認：Cursor、Gemini CLI、Copilot CLI。

### ほかのデバイスのエージェントから使う（`--mcp-http`）

tailnet のほかの場所にいるエージェント、たとえば Grok Bot（xAI のエージェント。クラウドのコンピュータが、Tailscale の OAuth apps で tailnet に入ります）には、同じツールをノードから HTTP で提供します。

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' --mcp-http
```

`run` は、URL（`http://reqcove.<tailnet>.ts.net:8090/mcp`）と、エージェントに渡すヘッダー（`Authorization: Bearer <トークン>`）を表示します。

- **Grok Bot**：Connect apps › Tailscale で tailnet に入れます（Tailnet Lock を使っていれば、そのデバイスに署名します）。次に Connect apps › カスタムコネクタを追加 で、種類に「リモート HTTPS」（名前は HTTPS ですが、tailnet の `http://` の URL で使えます。tailnet の中は WireGuard で暗号化されています）、サーバー URL にその URL、HTTP ヘッダーにキー `Authorization` と値 `Bearer <トークン>` を入れます。設定画面では、このコネクタは「エラー」でツール 0 個と表示されます。Grok Bot が tailnet に届くのはチャットの中だけだからです。チャットで頼んでください。ヘッダーの値は、画面に出さずにコピーできます：`printf 'Bearer %s' "$(cat ~/.reqcove/mcp-token)" | pbcopy`
- **ほかのコンピュータの Claude Code**（ヘッダーは `~/.claude.json` に保存されます）：
  `claude mcp add --transport http reqcove-remote http://reqcove.<tailnet>.ts.net:8090/mcp --header "Authorization: Bearer <トークン>"`
- **ほかのコンピュータの Codex**（トークンはその環境変数に入れます）：
  `codex mcp add reqcove-remote --url http://reqcove.<tailnet>.ts.net:8090/mcp --bearer-token-env-var REQCOVE_TOKEN`。
  Codex は MCP ツールを呼ぶたびに承認を求めます。承認を求められない `codex exec` では、このサーバーに `default_tools_approval_mode = "approve"` を設定します。

注意点：

- 呼べるのは、tailnet にある自分のデバイス（タグなし）で、トークンを持つものだけです（[SECURITY](SECURITY.md#mcp-over-http---mcp-http)）。タグ付きのデバイスは拒否します（`run` が一度ログに出します）。エージェントのデバイスを制限する目的で、タグを付けないでください。
- エージェントが読んだものは、そのエージェントのコンピュータと、モデルの提供元に渡ります（Grok Bot なら xAI のクラウド）。エージェントを止めるには、状態ディレクトリの `mcp-token` を削除して `run` を再起動するか（削除しない限り、トークンは起動のたびに同じです）、そのデバイスを tailnet から外します。
- `run` を再起動しても、再接続は要りません（止まっている間の呼び出しは失敗します）。記録は空から始まり、再起動前のカーソルは拒否します。
- `run` は、呼び出しごとにデバイスとツール名をログに出します（`--mcp-http: grokbot-user-1 (100.104.0.1) called "list_flows"`。引数は出しません）。トークンがない、または違うリクエストもログに出します。「確認します」と言うだけで呼んでいないエージェントは、ログに行が出ません。
- 通信は HTTP のままですが、tailnet の暗号化（WireGuard）の中を通ります。コンテナでも同じフラグで動き、ポートの公開は不要で、トークンは `docker logs` に出ます（[コンテナ](container.ja.md#3-エージェント)）。

確認状況：Grok Bot（status、フロー、ボディの取得。`run` の再起動後も同じチャットで継続。コンテナの `run`）、この Mac の Claude Code（`claude -p`）と Codex（`codex exec`）から tailnet 越しに確認（どちらも status を取得）。ほかのコンピュータ（tailnet にいる macOS の VM）からも、ノードの名前と IP の両方で呼べることを確認。

## 自分でフローを見る

### iPhone で見る（`--ui`）

通信を送っているアプリの横で、フローを見たいときに使います。

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' --ui
```

`run` は、ノードの 80 番ポートで読み取り専用のページを提供し、そのリンクを QR コードと一緒に表示します。iPhone のカメラで読み取ると、Safari で一覧が開きます。一覧は 1 秒ごとに新しいフローを追います（Split View でアプリと並べることもできます）。フローをタップすると、ヘッダーとボディを確認できます。MCP ツールが返すものと同じく、マスク済みです。

- 検索欄に入力すると、その場で URL とヘッダーを絞り込みます。「bodies too」をオンにすると、保持しているボディの先頭も対象になり、一覧は新しいフローを追わなくなります（すべての記録を調べるためです）。ステータス（2xx〜5xx、応答なし）や、フローのページからホストでも絞り込めます。
- Clear は、それまでのフローを一覧から隠します。「Show all」で戻ります。削除はしないので、エージェントからは引き続き見えます。
- Live / Paused で、新しいフローを追うかどうかを切り替えます。下にスクロールしている間は一覧を動かさず、新しいフローの件数を表示します。件数をタップすると表示されます。
- tailnet にある自分のデバイスからは、すべてのデバイスのフローが見えます。`--device` に指定した他人のデバイスからは、そのデバイス自身のフローだけが見えます（[それ以外のデバイスと、トークンの扱い](SECURITY.md#the-page---ui)）。
- リンクは起動のたびに同じなので、再起動後もブックマークから開けるはずです。リンクを変えるには、状態ディレクトリの `ui-token` を削除して起動し直します。
- Tailscale はオンにしておく必要があります。Exit Node や [Remote Proxy](#exit-node-を使わずに-wi-fi-のプロキシでつなぐ) は使っていなくてもかまいません。このページ自身の通信は記録されません。

確認状況：iPhone で確認（カメラから開く、新しいフローを追う、検索、Clear と Show all、`run` の再起動後に Safari で開き直す）。

### HAR ファイルに書き出す（`reqcove har`）

`reqcove run` が動いている間に実行します。

```sh
reqcove har > flows.har
```

フローを HAR 1.2 のファイルに、古い順で書き出します。デフォルトは新しい 1000 件です（`--limit 0` ですべて）。`--host`、`--device`、`--since 10m`、`--until`、`--status 4xx`、`--method`、`--user-agent` で絞り込めます。

- 中身は MCP ツールが返すものと同じです。届いた時点でマスク済みで、ボディは先頭だけです（切り詰めたボディは、コメントにその旨が入ります）。マスクで確認できなかったボディは含まれません。`run --no-redact` のときは何もマスクされず、ファイルのコメントにその旨が入ります。
- ファイルのパーミッションはシェルの設定に従うので、ほかのユーザーから読めることがあります（[SECURITY](SECURITY.md#what-is-recorded)）。

確認状況：Chrome の開発者ツール（Network）に読み込めることを確認（リクエスト、マスクされたヘッダー、レスポンスが見える）。未確認：Charles、Proxyman で開くこと。仕様から：HAR 1.2 の必須項目を出力（検証ツールは未実行）。

### mitmweb で見る（`--web`）

リクエストの編集やリプレイができる、mitmproxy 自身の画面を使いたいときに使います。

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' --web
```

mitmdump の代わりに mitmweb が起動します。このコンピュータでは `http://127.0.0.1:8081`（ほかの run が 8081 を使っていれば 8091〜8099。[アドレスは 2 つ](several-exit-nodes.ja.md#ポート)）、tailnet にある自分のデバイスからはノードの 8081 番ポートで、`run` が表示するリンクか QR コードから開けます。

- 何もマスクされません（[SECURITY](SECURITY.md#mitmweb---web)）。ボディは 1 つ 2 MB まで表示し、新しい 1 万件のフローと、合計 256 MB までのボディを保持します。
- リンクは起動のたびに同じです（トークンは状態ディレクトリの `web-token`）。再起動後は、リンクをもう一度開いてください。トークンなしのブックマークでは、トークンの入力を求められます。
- Capture タブの「Run SOCKS Proxy」は、オンのままにしてください。オフにすると、デバイスの HTTP(S) が止まります。そこにあるほかのモードは、Reqcove では使いません。変更した設定は、reqcove を再起動すると元に戻ります。

確認状況：Exit Node を使っている iPhone から確認。コードから（未確認）：mitmweb で設定を変えても、Reqcove の記録の範囲とマスクは変わらない。

## iPhone アプリ以外のクライアントを記録する

Reqcove が復号できるのは、クライアントが Reqcove を通して送り、かつ Reqcove の CA を信頼している通信です。CA を信頼するかどうかは、クライアントによって違います。

| クライアント | 復号できるもの | 確認に使ったもの |
|---|---|---|
| iPhone のアプリ、Safari、アプリ内の WebView（Flutter の `dart:io`、React Native も。自分の API にピンニングをするアプリ内の WebView も） | `--allow-hosts` のホストへの通信すべて | iPhone |
| 証明書ピンニングをするアプリ | なし。`--pass-hosts` で通せば動作し、接続だけを記録（[手順](#証明書ピンニングをするアプリを通す--pass-hosts)） | iPhone |
| Android の Chrome | iPhone と同じ | Android 14 のデバイス |
| Android のほかのアプリ | なし。システムの CA だけを信頼。自分のアプリは設定で変更可能（[手順](#android-を記録する)） | 同じデバイスと、サンプルアプリ |
| 本番の Web アプリ | デバイスとサーバーの間の通信（ページ、フロントエンドが呼ぶ API）。サーバーがその先へ送る通信は対象外 | iPhone |
| 自分で動かす Web アプリのバックエンド | ほかの API への呼び出し。Remote Proxy 経由（[手順](#web-アプリのバックエンドを記録する)） | Rails のアプリ（Net::HTTP、Faraday） |
| このコンピュータのアプリ、iOS シミュレーター | `--local-proxy` で対応（[手順](#ios-シミュレーターを記録する--local-proxy)） | この Mac の Chrome、iOS 27 のシミュレーターの Safari |
| 別の Mac | Exit Node の `--device` として。Tailscale のアプリで（[手順](#別の-mac-を記録する)） | macOS 27 の VM |

### 証明書ピンニングをするアプリを通す（`--pass-hosts`）

証明書ピンニングをするアプリは Reqcove の証明書を拒否するので、そのホストへのリクエストは失敗します。`reqcove status` が、該当するホストと、`run` に付ける `--pass-hosts` を表示します。付けて起動すると、そのホストは復号せずに通り、アプリが動きます。

```sh
reqcove run --device iphone --allow-hosts '*' --pass-hosts '*.example-cdn.com,api.example.com'
reqcove run --device iphone --allow-hosts '*' --pass-hosts @pass-hosts.txt   # 1 行に 1 ホスト
```

- そのホストは、接続だけを記録します（ホスト、接続先サーバー、時刻、バイト数：`list_passthrough`）。URL や中身は記録しません。
- `--rules` と `--upstream-proxy` の対象外になります。
- TLS ハンドシェイクのあとで行うピンニングは、どこにも表示されません。
- 自分のアプリなら、ピンニングを外したビルドを使ってください。Android のアプリが CA を拒否するのは、別の理由です（[Android](#android-を記録する)）。

確認状況：iPhone で確認。

### Android を記録する

Android 7 以降向けに作られたアプリは、標準ではシステムの CA だけを信頼し、自分で入れた CA（設定から CA 証明書として入れたもの）は信頼しません。アプリが `network_security_config` で自分で入れた CA を許可していれば別です。試したデバイスでは、Chrome は復号でき、ほかのアプリはすべて CA を拒否しました。Android のデバイスには、`reqcove status` がそう案内します（Tailscale が報告する OS で判断します）。

- `--allow-hosts` は、調べたいホストに絞ってください。それ以外のホストは復号せずに通すので、アプリは動きます。
- 自分のアプリなら、デバッグビルドの `network_security_config` で、ユーザーが入れた CA を信頼させます。

```xml
<network-security-config>
  <debug-overrides>
    <trust-anchors>
      <certificates src="user" />
    </trust-anchors>
  </debug-overrides>
</network-security-config>
```

確認状況：Android 14 のデバイス（Chrome は復号、ほかのアプリはすべて拒否）と、サンプルアプリ（`domain-config` でこのように指定したホストは復号、指定していないホストは CA を拒否）と、上の `debug-overrides` を書いたデバッグ用のビルド（両方のホストから応答あり）で確認。

### iOS シミュレーターを記録する（`--local-proxy`）

シミュレーターのアプリはこのコンピュータのネットワークを使うので、Exit Node では中継できません。`--local-proxy` を付けると、代わりに `127.0.0.1:8082` に HTTP プロキシを開き、そこを通ったリクエストを `local` というデバイスとして記録します。

```sh
reqcove run --allow-hosts api.example.com --local-proxy   # iPhone も記録するなら --device も
```

- macOS：Charles や Proxyman と同じように、`run` がシステムの Web プロキシ（HTTP と HTTPS、有効なネットワークサービスすべて）をこのプロキシに向け、止まるとき（Ctrl-C、`kill`、ターミナルを閉じたとき）に元の設定へ戻します。起動中のシミュレーターには、Reqcove の CA も追加します（`xcrun simctl keychain … add-root-cert`）。あとから起動したシミュレーターには、表示されるコマンドで追加してください。
- Linux：設定は何も変更しません。アプリをプロキシに向け（`HTTPS_PROXY=http://127.0.0.1:8082`）、CA を信頼させてください。
- シミュレーターだけでなく、このコンピュータのすべてのアプリがこのプロキシを通ります。復号して記録するのは `--allow-hosts` のホストだけですが、そのホストは、Reqcove の CA を信頼していないアプリ（Mac の Safari など）ではつながらなくなります。
- `kill -9` や異常終了のあとは、次の `run` か `reqcove cleanup` がプロキシの設定を戻すまで（またはシステム設定で自分で戻すまで）、システムのプロキシを使うアプリがつながりません。
- このコンピュータ、LAN、tailnet（`*.ts.net` も）、`*.local` はプロキシの例外に入れるので、これまでどおり直接つながります。名前解決はこのコンピュータと同じ方法で行い（VPN、split DNS、検索ドメインも有効）、`--dns` は使いません。このコンピュータ自身やリンクローカルアドレスに解決される名前は、`/etc/hosts` にあるものを除いて拒否します（[SECURITY](SECURITY.md#the-local-proxy---local-proxy)）。
- 自動プロキシ構成（PAC）と認証付きプロキシの設定は、変更しません。

このコンピュータのブラウザも、警告で止めるのではなく記録したいときは（`local` として、シミュレーターの通信と一緒に記録されます）、このコンピュータに Reqcove の CA を一度信頼させます。コマンドは `run` が表示し、やめ方は `reqcove status` と `reqcove cleanup` が表示します。信頼させると、CA の秘密鍵を持つ人は、このコンピュータに対しても任意の HTTPS サイトになりすませます（[SECURITY](SECURITY.md#the-local-proxy---local-proxy)）。

- macOS（TLS だけを信頼。パスワードを求められます）：`security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem`。Firefox は、独自の証明書ストアを使うことがあります。やめるには、`reqcove status` が表示するコマンドを実行するか、キーチェーンアクセスで CA を削除します（信頼の設定も一緒に消えます）。
- Debian と Ubuntu：`sudo cp ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/reqcove.crt && sudo update-ca-certificates`。Fedora：`/etc/pki/ca-trust/source/anchors/` に置いて `sudo update-ca-trust`。
- Linux の Chrome と Chromium：`certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n Reqcove -i ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem`。Node：`NODE_EXTRA_CA_CERTS=` にそのファイルを指定します。Python：更新後のシステムの CA バンドルを指定します（そのファイルだけを指定すると、ほかの CA がすべて使えなくなります）。

確認状況：macOS 27 で確認（信頼させるコマンドと Reqcove による信頼の確認、やめ方の表示、キーチェーンアクセスでの削除、Mac の Chrome で許可したホストが警告なしに開けて記録されること、本物の `networksetup` でシステムの Web プロキシが 127.0.0.1:8082 に向き、Ctrl-C で元に戻ること、起動中のシミュレーターに CA が入ること、iOS 27 のシミュレーターの Safari の通信が `local` として復号・記録されること）。未確認：プロキシの例外でのアドレスの書き方、PAC や認証付きプロキシのある環境、Linux。

### Web アプリのバックエンドを記録する

Web アプリがほかの API を呼ぶ通信（Rails のサーバーが決済 API を呼ぶ、など）は、iPhone ではなくサーバーから出ます。Reqcove に見えるのは、サーバーがその通信を Reqcove に通し、Reqcove の CA を信頼しているときだけです。tailnet にある自分のマシンで動くサーバーなら、そのマシンを `--device` に指定し、サーバーにノードの [Remote Proxy](#exit-node-を使わずに-wi-fi-のプロキシでつなぐ) を指定します。

```sh
reqcove run --device dev-server --allow-hosts api.example.com
# dev-server で：変数は両方指定（Ruby の Net::HTTP は HTTPS でも http_proxy を見る）
# CA バンドルには Reqcove の CA を追加（システムの CA バンドルと mitmproxy-ca-cert.pem を連結）
http_proxy=http://100.x.y.z:8080 https_proxy=http://100.x.y.z:8080 SSL_CERT_FILE=bundle.pem bin/rails server
```

- 呼び出しは、そのマシンの名前で記録されます。変更するのは、サーバーの環境変数だけです。
- データベースや Redis への接続は、80 番・443 番の HTTP(S) ではないので見えません。
- ブラウザからアプリへのリクエストは、別の経路です。iPhone からなら、許可したホストへのリクエストを `map_remote` で開発サーバーに送れます（[ルール](#ルールを書く--rules)）。

確認状況：この Mac をデバイスにして、Rails 8 のアプリから Net::HTTP と Faraday で API を呼んで確認（CA がないと Ruby が証明書を拒否して TLS の失敗が記録され、CA があると両方の呼び出しが記録されました）。未確認：ほかのクライアント、別のマシンのサーバー。

### Exit Node を使わずに Wi-Fi のプロキシでつなぐ

ノードは **Remote Proxy** も提供しています。ノードの tailnet アドレスのポート 8080（`--proxy-port`）で動く HTTP プロキシで、`--device` のデバイスが使えます。iPhone では、Exit Node を選ぶ代わりに、Wi-Fi のプロキシ設定（手動）にこれを指定できます。モバイル通信にはプロキシ設定がないので、Wi-Fi でのみ使えます。

| | Exit Node | Wi-Fi のプロキシ |
|---|---|---|
| このコンピュータを通る通信 | iPhone のすべての通信（DNS、HTTP(S)、ほかのポート） | プロキシ設定に従うアプリの HTTP(S) |
| それ以外 | なし | iPhone の Wi-Fi から直接インターネットへ（記録なし） |
| モバイル通信 | 利用可 | 利用不可 |
| Tailscale アプリ | Exit Node を選択 | 接続したままにするだけ |

プロキシを通った通信は、Exit Node のときと同じく、このコンピュータからインターネットに出ます。名前解決も、このコンピュータで行います。

確認状況：iPhone で確認（Safari の通信が記録され、`--allow-hosts` にないサイトもこれまでどおり開けました）。

### 別の Mac を記録する

`--device` に指定した Mac で、Tailscale のアプリから Exit Node を選ぶと、iPhone と同じように記録されます（[手順](another-mac.ja.md)）。Homebrew のオープンソース版の `tailscaled` では、Exit Node は選ばれた表示になりますが、その Mac の通信は通りません。確認状況：macOS 27 の VM で確認。未確認：その Mac の iOS シミュレーター（シミュレーターが Reqcove の CA を信頼していれば、Mac の通信と一緒に通るはず）。

## リクエストの行き先を変える

### ルールを書く（`--rules`）

ルールは YAML ファイルに書き、`--allow-hosts` のホストにだけ適用されます。アプリのリクエストを、このコンピュータの開発サーバーに送る例です。

```yaml
map_remote:                     # mitmproxy の書式（map_local、modify_headers も同じ）
  - "|https://api.example.com/|http://localhost:3000/"
keep_host_header: true          # Reqcove 独自：map_remote でもアプリの Host を残す
```

```sh
reqcove run --device iphone --allow-hosts api.example.com --rules rules.yaml
```

- `map_remote`、`map_local`、`modify_headers` は mitmproxy の機能で、mitmproxy 自身のコードが処理します。相対パスは、ルールファイルの場所が基準です。
- `map_remote` は URL を書き換えるので、`keep_host_header` を true にしない限り、`Host` ヘッダーも変わります。上の例のように、スキームも書いてください。アプリは `https` で送り、平文のサーバーは TLS に応答できないためです。
- `map_local` が応答するのは、ボディが 1 MiB 以下で長さが分かっているリクエストだけです。それ以外は本来の宛先へ送ります（記録にその旨が残ります）。長さのない HTTP/2 の GET にも応答し、一緒に送られてきたボディはすべてメモリに保持します。`--device` のデバイス上のアプリや Web ページも（`--local-proxy` なら、このコンピュータのアプリも）、ルールに合うホストへのこうしたリクエストの送り手になりえます。とても大きなボディだと mitmproxy のメモリが尽き（reqcove が起動し直します）、その間デバイスの通信が止まります。
- 他人が作ったルールファイルは、中身を読んでから使ってください。ルールは、アプリのリクエストを Cookie やトークンごと、書かれた先へ送れます。

`resolve` は、リクエストをそのままにして、接続先だけを変えます。ステージングサーバーや新しいロードバランサー向けです。

```yaml
resolve:                        # Reqcove 独自：Host と SNI はそのままで、接続先だけ変える
  - "shop.example.com=203.0.113.10"
  - "auth.example.com=192.168.1.20:8443"
```

- その名前へのリクエストを、指定した IPv4 アドレスへ送ります（このコンピュータや LAN のアドレスも指定できます）。`Host`、SNI、記録される URL は変わらず、TLS もその名前で検証します。接続先のサーバーには、その名前の証明書が必要です（証明書のないローカルの HTTPS サーバーでは 502 になります）。平文の HTTP は検証されません。
- ポートを省略すると、リクエストのポート（アプリの 80 番か 443 番、または `map_remote` の URL のポート）を使います。`map_remote` のあとでは、書き換え後の URL のホストが対象の名前になり、SNI もそれになります。
- 名前解決はこれまでどおり行われ（iPhone が行い、Remote Proxy ではこのコンピュータが行います）、先に本物のサーバーへ接続します。公開の DNS で解決できない名前や、接続を拒否する本物のサーバーは、接続先を変えられません。
- 名前は `--allow-hosts` に入っている必要があり、名前ごとに別のアドレス（またはポート）が必要です。mitmproxy が、接続をアドレス単位で使い回すためです。
- 拒否するもの：`0.0.0.0/8`、リンクローカル（クラウドのメタデータ）、マルチキャスト、Tailscale の 100.100.100.100（[SECURITY](SECURITY.md#rules---rules)）。`--upstream-proxy` と一緒に使う `resolve` も拒否します。

ファイルは、mitmproxy の起動時に読み込みます（`run` の起動時と、reqcove が mitmproxy を再起動するとき）。`--rules-reload` を付けると、変更が落ち着いた時点で読み直し、そのあとに始まるリクエストから適用します。処理中のリクエストは、始まったときのルールのままです。

- 読み込めないファイルのときは前のルールのまま動き、`run` と `reqcove status` が理由を表示します。ただし、その間に mitmproxy が再起動すると、起動時と同じく `run` が止まります。
- ファイルに書き込めるもの（エージェントを含む）が、再起動なしで、デバイスのリクエストの行き先を変えられるようになります。

コードから：変更は 2 秒ほどで読み直される。

### 上流プロキシに回す（`--upstream-proxy`）

Reqcove で記録しながら、同じリクエストを Burp Suite（や ZAP、Charles など）でも見たいときに使います。

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' \
  --upstream-proxy http://127.0.0.1:8080
```

復号したリクエストはプロキシへ送り（HTTPS は CONNECT トンネル、平文の HTTP はプロキシ宛てのリクエスト）、サーバーへは直接接続しません。プロキシにはマスクされていない中身がすべて見え、Burp はそれをプロジェクトに保存します。Burp の Intercept はオフにしてください。オンのままだと、リクエストがそこで止まります。

- `--allow-hosts` にないホストへの接続は、これまでどおり直接通ります。ただし、許可したホストへの復号済みの接続に相乗りした、ほかのホスト宛てのリクエスト（HTTP/2 の接続の再利用）は、記録されないままプロキシを通ります。許可したホストへのほかのプロトコル（MQTT など）は、サーバーへ直接接続します。TLS を使うものは、プロキシの CA を使っている間は失敗します（サーバーの証明書を、その CA で検証するためです）。
- Burp は HTTPS のホストに、SNI の名前をこのコンピュータで名前解決し直して接続します。そのため、Exit Node がこのコンピュータと LAN を宛先として拒否していても、Burp の接続先には効きません（[SECURITY](SECURITY.md#an-upstream-proxy---upstream-proxy)）。`--allow-hosts` は、調べるホストだけにしてください（`'*'` のときは `run` が警告します）。同じ理由で、`resolve` のルールは拒否します。プロキシ側の設定（Burp の Hostname resolution overrides）を使ってください。
- プロキシを通る HTTPS は、プロキシの CA だけで検証します。このコンピュータの Burp の CA は、起動時に `http://burp/cert` から取得します。ほかの復号するプロキシ（ZAP、Charles など）には、`--upstream-ca FILE`（PEM か DER）で CA を指定してください。どちらでもなければ、公開の CA で検証します（復号しないプロキシ向け）。
- Reqcove はプロキシに直接接続し、システムのプロキシ設定は使いません。ただし、システムのプロキシを自分に向けるプロキシ（Charles は、Proxy メニューの「macOS Proxy」をオフにしない限りそうします）と `--local-proxy` は、同じ設定を取り合い、止まるときに相手の設定へ戻してしまいます。`--local-proxy` と一緒に使うときは、プロキシ側のその機能をオフにしてください。
- Burp での動作：平文の HTTP は IP アドレスで表示され、名前は `Host` ヘッダーで分かります。リクエストのボディは、すべて届くまで Burp が保持します。HTTP/1.1 のクライアントへの Server-Sent Events は失敗します（iOS アプリの多くが使う HTTP/2 では流れます）。SNI のない、IP アドレス宛ての HTTPS は失敗します（Burp が証明書に入れるアドレスの形式を、mitmproxy が受け付けないためです）。`--web` と一緒に使うと、mitmweb からリプレイした平文の HTTP リクエストは、プロキシ自身に送られます。

確認状況：Burp Suite Community 2026.10 で確認（SNI の名前で名前解決し直すことを含む）。Charles 5.0b12（復号する設定）でも、`--upstream-ca` を付けて確認（付けないと、証明書を信頼できなかったことが記録に残ります）。このコンピュータで Burp 以外のプロキシを使うときも、`run` は起動時に `http://burp/cert` を取りに行き、そこで失敗します（Charles の一覧に出ます）が、動きは変わりません。未確認：ほかのプロキシ。コードから：ほかのプロトコルがサーバーへ直接接続すること。

## オプション

`reqcove run` のオプション：

| | |
|---|---|
| `--device NAME` | 中継するデバイス。マシン名、デバイス名（タグのない自分のデバイスに限る）、tailnet の IP アドレス、StableID のいずれか。複数は繰り返して指定 |
| `--allow-hosts HOSTS` | 復号して記録するホスト。`api.example.com`、`*.example.com`（そのドメイン自身とすべてのサブドメイン）、すべてを対象にする `'*'`、または `@FILE`（1 行に 1 つ。`#` 以降はコメント）。指定しない場合、通信は中継するが記録しない |
| `--pass-hosts HOSTS` | 許可したホストのうち、復号せずに通すもの。書き方は同じ（`'*'` は不可）。[証明書ピンニング](#証明書ピンニングをするアプリを通す--pass-hosts) |
| `--rules FILE` | 許可したホストに適用する[ルール](#ルールを書く--rules) |
| `--rules-reload` | そのファイルが変わるたびに読み直す |
| `--upstream-proxy URL` | 復号したリクエストを[上流の HTTP プロキシ](#上流プロキシに回す--upstream-proxy)に回す |
| `--upstream-ca FILE` | そのプロキシの CA（PEM か DER） |
| `--local-proxy` | このコンピュータのアプリ用のプロキシ（`127.0.0.1:8082`）。[iOS シミュレーター](#ios-シミュレーターを記録する--local-proxy) |
| `--proxy-port N` | [Remote Proxy](#exit-node-を使わずに-wi-fi-のプロキシでつなぐ) のポート。デフォルトは 8080。0 で無効 |
| `--ui` | [フローを見る読み取り専用のページ](#iphone-で見る--ui)。ノードの 80 番ポート |
| `--web` | mitmdump の代わりに [mitmweb](#mitmweb-で見る--web) を起動。マスクなし |
| `--mcp-http` | [MCP ツールを HTTP でも提供](#ほかのデバイスのエージェントから使う--mcp-http)。ノードの 8090 番ポート |
| `--dns SERVERS` | Exit Node が使う上流 DNS（カンマ区切り）。デフォルトは `1.1.1.1:53`（ポートは省略可）。`system` で `/etc/resolv.conf` の最初の nameserver |
| `--no-redact` | シークレットをマスクせずに記録 |
| `--state DIR` | 状態ディレクトリ。デフォルトは `~/.reqcove`。ノードキー、CA とその秘密鍵を保存。新しいか空のディレクトリ、または reqcove が以前使ったものに限る。`--state ~/x` とスペースを空けて指定（`--state=~/x` は拒否）。CA のないディレクトリには `~/.reqcove` の CA をコピーし、`reqcove-NAME` という名前の新しいディレクトリでは、ノード名もそれになる：[複数の Exit Node](several-exit-nodes.ja.md) |
| `--hostname NAME` | ノードの名前。デフォルトは `reqcove`。状態ディレクトリに保存 |
| `--verbose` | tsnet のバックエンドと、フローごとの判断をログに出力 |
| `--uvx PATH` | 使用する uvx |
| `--python VERSION` | uvx が取得する Python。デフォルトは 3.14 |
| `--mitmproxy-spec SPEC` | uvx が取得する mitmproxy。デフォルトは `mitmproxy==12.3.1` |

ほかのコマンド（`init` と `version` 以外は、`--state DIR` も指定可能）：

| | |
|---|---|
| `reqcove status` | reqcove の状態と次の手順。`--json` で `status` ツールの JSON を出力。`--uvx PATH` |
| `reqcove mcp` | このコンピュータのエージェント用の MCP サーバー |
| `reqcove har` | [フローを HAR ファイルに出力](#har-ファイルに書き出すreqcove-har)。`--host`、`--device`、`--since`、`--until`、`--status`、`--method`、`--user-agent`、`--limit N` |
| `reqcove init` | [エージェント用の Skill](#使い方を教える-skill-を入れるreqcove-init)。`--client NAME`、`--print`、`--uninstall` |
| `reqcove cleanup` | 元に戻す手順の表示。`--delete-state`、`--hostname NAME` |
| `reqcove version` | バージョンの表示 |

コードから（フラグのヘルプに基づく記述で、このガイドでは未確認）：`--proxy-port 0`、`--hostname`、`--verbose`、`--uvx`、`--python`、`--mitmproxy-spec`、`status --json`。

## MCP ツール

| ツール | |
|---|---|
| `list_flows` | フローを新しい順に一覧。デバイス、ホスト（サブドメインを含む）、時間（`since: "10m"`）、ステータスコード（`404`、`4xx`、`none`）、メソッド、User-Agent（アプリ名など、含まれる文字列で指定。アプリのバンドル ID は通信に含まれない）で絞り込み。ページング対応。ホストが 1 件も一致しないときは、記録にある似たホスト（`acmeshop.com` に対する `acme-shop.com` など）を `similar_hosts` で返す |
| `search_flows` | URL とヘッダーのテキストを検索（`bodies` を指定するとボディの先頭も対象）。絞り込みと `similar_hosts` は同じ |
| `get_flow` | フローを 1 件取得。ボディは `bodies` を指定したときだけ |
| `summarize` | ホスト、User-Agent、ステータスコード、メソッド、デバイス、Content-Type ごとの件数。絞り込みと `similar_hosts` は同じ |
| `list_devices` | 中継しているデバイスと、それぞれの件数、最終アクティビティ |
| `list_tls_failures` | デバイスが拒否した TLS ハンドシェイク。多くは証明書ピンニングか、まだ信頼されていない CA が原因 |
| `list_passthrough` | `--pass-hosts` のホストへの接続。ホスト、接続先サーバー、時刻、バイト数。URL や中身はなし |
| `capture_stats` | mitmproxy の状態、記録がカバーしている期間、ドロップ数 |
| `status` | セットアップが完了しているか。未完了なら次の手順 |

## 制限事項

主な制限事項は [README](../README.ja.md#制限事項) にあります。そのほかの制限事項は次のとおりです。

- IPv6 は拒否します。アプリは、すぐに IPv4 にフォールバックします。
- QUIC は Apple 宛てを除いてドロップするので、アプリは TCP にフォールバックします。判定はホストではなくアドレスで行うため、`--allow-hosts` にないホストの QUIC も（`--allow-hosts` を指定しないときも）フォールバックします。443 番以外のポートの QUIC はそのまま通し、記録しません。
- mitmproxy は WebSocket のメッセージを、届ききるまで 1 つずつ保持します。巨大なメッセージが来ると、メモリを多く使います。mitmproxy がメモリ不足で落ちると reqcove が再起動し、再起動しても 1 分以内に落ちることが 5 回続くと、`run` が止まります。
- Exit Node 経由の通話は未確認です。
- 機能ごとの制限事項は、それぞれの節にあります：[`--ui`](#iphone-で見る--ui)、[`--web`](#mitmweb-で見る--web)、[`--local-proxy`](#ios-シミュレーターを記録する--local-proxy)、[ルール](#ルールを書く--rules)、[上流プロキシ](#上流プロキシに回す--upstream-proxy)。

## セキュリティ

詳しくは [SECURITY.md](SECURITY.md)（英語）にあります。オプションごとの注意は、上の各節からリンクしています。それ以外の主な項目は次のとおりです。

- [記録するもの](SECURITY.md#what-is-recorded)：`--allow-hosts` のホストだけで、Apple のホストは対象外。マスクで見つかるものと、見つからないもの。
- [エージェントが読んだものの行き先](SECURITY.md#what-the-agent-sees-goes-further)：モデルの提供元。ボディがエージェントに指示しようとすることもあります（[プロンプトインジェクション](SECURITY.md#prompt-injection)）。
- [デバイスから届く範囲](SECURITY.md#what-the-devices-can-reach)：このコンピュータ、LAN、tailnet は対象外。
- [CA の秘密鍵](SECURITY.md#the-cas-private-key)：状態ディレクトリに保存。
- [Exit Node の DNS](SECURITY.md#the-exit-nodes-dns)（`--dns`）と、[コンテナ](SECURITY.md#in-a-container)。
