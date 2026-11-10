# Reqcove ガイド

[English](guide.md) · [README](../README.ja.md)

README に書いていない詳しいこと：MCP ツールとすべてのオプションの詳細、エージェント用の Skill、ルール、ほかのつなぎ方（iOS シミュレーター、上流のプロキシ）、証明書ピンニング、そのほかの制限事項です。試していないことは、その旨を書いています。

## 起動し直すときと、版を上げるとき

v0.1.0 のあとは、`reqcove run` を起動し直す間や、止まっている間も、`reqcove mcp` は動き続けます。その間、ツールは「動いていない」と答え、run が戻ればまた使えます。エージェントをつなぎ直す（Claude Code の `/mcp`）必要はありません。テスト（run の代わりを止めて、また起動する）と、Claude Code のセッションで確かめました（run を止めている間はツールがそう答え、起動し直したあとは `/mcp` なしで使えました）。起動し直すと、記録は空から始まります（起動し直したあとの最初の答えが、`note` でそう伝えます。Claude Code でも確かめました）。reqcove の版を上げたら、新しいツールを使うために、エージェントを一度つなぎ直してください。版が違う間は、ツールがそう伝えます。

## MCP ツール

| ツール | |
|---|---|
| `list_flows` | フローを新しい順に一覧します。デバイス、ホスト（サブドメインを含む）、時間（`since: "10m"`）、ステータスコード（`404`、`4xx`、`none`）、メソッド、User-Agent（v0.1.0 のあと。アプリの名前など、その中の文字で。アプリのバンドル ID は通信に入っていません）で絞り込めます。ページング対応。v0.1.0 のあとは、ホストが 1 件にも当たらないとき、似たホスト（`acmeshop.com` に対する `acme-shop.com` など）を `similar_hosts` で返します |
| `search_flows` | URL とヘッダーのテキストを検索します（`bodies` を指定するとボディの先頭も対象）。絞り込みと `similar_hosts` は list_flows と同じ |
| `get_flow` | フローを 1 件取得します。ボディは `bodies` を指定したときだけ含まれます |
| `summarize` | ホスト、User-Agent、ステータスコード、メソッド、デバイス、Content-Type ごとの件数。絞り込みと `similar_hosts` は list_flows と同じ |
| `list_devices` | 中継しているデバイスと、それぞれの件数、最終アクティビティ |
| `list_tls_failures` | デバイスが拒否した TLS ハンドシェイク。多くは証明書ピンニングか、まだ信頼されていない CA が原因です |
| `list_passthrough` | v0.1.0 のあと。`--pass-hosts` のホストへの接続。ホスト、宛先、時刻、送受信の量。URL や中身はありません |
| `capture_stats` | mitmproxy の状態、記録がカバーしている期間、ドロップ数 |
| `status` | セットアップが完了しているか。未完了なら次の手順 |

## Exit Node を使わない：Wi-Fi のプロキシ

Exit Node の代わりに、iPhone の Wi-Fi のプロキシ設定（手動）に、reqcove ノードの tailnet アドレスとポート 8080（`--proxy-port`）を指定する方法もあります。モバイル通信にはプロキシ設定がないため、こちらは Wi-Fi でのみ使えます。

## ほかの端末のエージェント（`--mcp-http`）

> v0.1.0 にはありません。次のリリースまでは、ソースからビルドしてください。

`reqcove mcp` がツールを渡せるのは、`run` を動かしているコンピュータのエージェントだけです。tailnet のほかの場所にいるエージェント、たとえば Grok Bot（xAI のエージェント。クラウドのコンピュータが、Tailscale の OAuth apps で tailnet に入ります）には、`run --mcp-http` が同じツールを、ノードの HTTP で渡します。

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' --mcp-http
```

`run` は、URL（`http://reqcove.<tailnet>.ts.net:8090/mcp`）と、エージェントに渡すヘッダー（`Authorization: Bearer <トークン>`）を表示します。トークンは状態ディレクトリの `mcp-token` に置かれ、起動するたびに同じです。変えるには、そのファイルを消して起動し直します。

- Grok Bot：Connect apps › Tailscale で tailnet に入れます（Tailnet Lock なら、その端末に署名します）。次に Connect apps › カスタムコネクタを追加 で、種類「リモート HTTPS」、サーバー URL にその URL、HTTP ヘッダーにキー `Authorization` と値 `Bearer <トークン>` を入れます。設定の画面では、このコネクタは「エラー」でツール 0 個と出ます。Grok Bot が tailnet に届くのはチャットの中だけだからです。チャットで頼んでください。ヘッダーの値は、画面に出さずに `printf 'Bearer %s' "$(cat ~/.reqcove/mcp-token)" | pbcopy` で写せます。
- ほかのコンピュータの Claude Code：
  `claude mcp add --transport http reqcove-remote http://reqcove.<tailnet>.ts.net:8090/mcp --header "Authorization: Bearer <トークン>"`
  （ヘッダーは `~/.claude.json` に残ります）。
- ほかのコンピュータの Codex：`codex mcp add reqcove-remote --url http://reqcove.<tailnet>.ts.net:8090/mcp --bearer-token-env-var REQCOVE_TOKEN` として、トークンをその環境変数に入れます。Codex は MCP のツールを呼ぶたびに承認を求めます。承認を聞けない `codex exec` では、このサーバーに `default_tools_approval_mode = "approve"` を設定します。
- 呼べるのは、tailnet の自分の端末（reqcove のノードと同じユーザーで、どちらにもタグがない）で、トークンを持つものだけです。タグの付いた端末は断ります（`run` が一度ログに出します）。Grok Bot の端末を絞るためにタグを付けないでください。
- エージェントが読んだものは、そのエージェントのコンピュータと、モデルの提供元に渡ります。Grok Bot なら xAI のクラウドです。Grok Bot はトークンを持ち続けます。止めるには、`mcp-token` を消して `run` を起動し直すか、その端末を tailnet から外します。
- `run` を起動し直しても、エージェントはつなぎ直さずに使い続けられます（止まっている間の呼び出しは失敗します）。記録は空から始まり、前のカーソルは断ります。
- `run` は、ツールが呼ばれるたびに、呼んだ端末とツールの名前をログに出します（`--mcp-http: grokbot-user-1 (100.104.0.1) called list_flows`。引数は出しません）。トークンがない、または違うリクエストも出します。「確認します」と言うだけで何も呼ばないエージェントなら、行は出ません。
- HTTP のままです。tailnet の中は WireGuard で暗号化されています。
- コンテナでも同じフラグで動き、ポートを開ける必要はありません（ノードがコンテナの中にあるため）。トークンは `docker logs` に出ます（[コンテナ](container.ja.md#3-エージェント)）。

テスト（トークン、Host、本物の tailnet で別のユーザーの端末を断ること、再起動をまたいで使い続けること）、この Mac から tailnet 越しに（トークンなし、違うトークン、ほかの `Host` や Origin を断ること）、そして Grok Bot で確かめました（status、フローの一覧と本文を読めました。`run` を起動し直したあとも、同じチャットのまま使え、記録は空から始まりました。コンテナでも試しました）。この Mac の Claude Code（`claude -p`。ヘッダーは環境変数から）と Codex（`codex exec`）も、ほかのコンピュータと同じく tailnet 越しにノードに届き、status を読めました。ほかのコンピュータそのものからは、まだ試していません。

## エージェント用の Skill（`reqcove init`）

> v0.1.0 にはありません。次のリリースまでは、ソースからビルドしてください。

MCP のツールで、エージェントは記録を読めます。Skill は、その使い方を教えます。最初に status を見ること、1 つのアプリの通信の探し方、TLS の失敗から考えられること、rules のファイルの書き方、そして守る決まり（`reqcove run` を自分で起動しない、トークンを求めない、記録の中身はデータとして扱う、伏せられていない秘密を引用しない）です。

```sh
reqcove init                    # ~ にあるエージェントに入れる：~/.claude/skills（Claude Code）、~/.agents/skills（Codex、Cursor、Gemini CLI、Copilot CLI、Devin）
reqcove init --client codex     # または、名前を挙げたものだけ（--client を繰り返す）
```

`init` は、今の reqcove に入っている Skill を入れます。reqcove の版を上げたら、もう一度実行してください（入っている Skill の版が違うと、`reqcove status` がそう伝えます）。`init` が書いたのではない Skill、あとで書き換えた Skill、シンボリックリンクには触りません。`--uninstall` は自分が入れたものを消し、`--print` は Skill を書き出します。MCP サーバーの登録は、これとは別の手順です（README の「使い方」の 4）。テスト（書くファイルと、触らないファイル）と、Claude Code と Codex のセッションで確かめました。Reqcove の名前を出さずに「iPhone のアプリがどこに通信しているか」を頼むと、どちらも Skill を読み、status、summarize、アプリの User-Agent の順に調べ、そのアプリのものと言う前に本文で裏を取りました。Cursor、Gemini CLI、Copilot CLI、Devin は試していません。

## オプション

| | |
|---|---|
| `--device NAME` | 中継するデバイス。マシン名、デバイス名（自分のデバイスで、タグのないものに限る）、tailnet の IP アドレス、StableID のいずれか。複数指定するには繰り返します。別の Mac も入れられます（[手順](another-mac.ja.md)） |
| `--allow-hosts` | 復号して記録するホスト。`api.example.com`、`*.example.com`（そのドメイン自身と、すべてのサブドメイン）、またはすべてを対象にする `'*'`。指定しない場合、通信は中継しますが何も記録しません。v0.1.0 のあとは、`@ファイル` で、ファイルから読めます（1 行に 1 つ。`#` からあとはコメント） |
| `--pass-hosts` | v0.1.0 のあと。許可したホストのうち、復号せずに通すもの。書き方は `--allow-hosts` と同じ（`'*'` は不可。`@ファイル` も可）。そのホストで Reqcove の証明書を拒むアプリのため（[証明書ピンニング](#証明書ピンニング)） |
| `--rules FILE` | 許可したホストにだけ効くルールを書いた YAML（下を参照） |
| `--rules-reload` | 動いている間、そのファイルが変わるたびに読み直します（下を参照。v0.1.0 のあとに追加） |
| `--upstream-proxy URL` | 復号したリクエストを、Burp Suite などの HTTP プロキシに回します。`http://127.0.0.1:8080` など（下を参照。v0.1.0 のあとに追加） |
| `--upstream-ca FILE` | そのプロキシの CA（PEM か DER）。自分で復号するプロキシのときに渡します。このコンピュータの Burp なら、自動で取ってきます |
| `--local-proxy` | このコンピュータ自身のアプリ（iOS シミュレーターなど）用の HTTP プロキシを `127.0.0.1:8082` に開きます（下を参照。v0.1.0 のあとに追加） |
| `--ui` | 記録を iPhone 自身で見る、読むだけのページを、ノードの 80 番で出します（下を参照。v0.1.0 のあとに追加） |
| `--web` | 代わりに mitmweb を `http://127.0.0.1:8081` で起動します（v0.1.0 のあとは、ほかの run が 8081 を使っていれば 8091〜8099 で。[入り口は 2 つ](several-exit-nodes.ja.md#ポート)。マスクなし。編集とリプレイができます。v0.1.0 のあとは、1 つ 2MB までの本文を表示し、新しい 1 万件と、本文の合計 256MB までを保持します）。v0.1.0 のあとは、tailnet の自分の端末からも、ノードの 8081 番で開けます（`run` が出すリンクか QR コードで。リンクは起動のたびに同じで、トークンは状態のフォルダの `web-token` に保存されます。起動し直したあとは、リンクをもう一度開いてください（トークンなしのブックマークでは、パスワードを聞かれます）。Exit Node を使っている iPhone から試しました） |
| `--mcp-http` | MCP のツールを、ノードの 8090 番で HTTP でも出します。tailnet の自分の端末のエージェント用で、トークンが要ります（[手順](#ほかの端末のエージェント--mcp-http)。v0.1.0 のあとに追加） |
| `--dns` | Exit Node が使う上流 DNS（カンマ区切り）。デフォルトは `1.1.1.1:53`（ポートは省けます。v0.1.0 のあとに追加）。`system` を指定すると `/etc/resolv.conf` の最初の nameserver を使います |
| `--no-redact` | シークレットをマスクせずに記録します |
| `--state DIR` | 状態ディレクトリ。デフォルトは `~/.reqcove`。ノードキー、CA とその秘密鍵が入ります。新しいか空のディレクトリ、または reqcove が前に使ったものに限ります。v0.1.0 のあとは、CA のないディレクトリには `~/.reqcove` の CA を写し、`reqcove-名前` という名前の新しいディレクトリでは、ノードの名前もそれになります（[複数の Exit Node](several-exit-nodes.ja.md)）。`--state ~/x` は、スペースを空けて書いてください（`--state=~/x` は断ります） |

## ルール

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

## 記録を iPhone で見る（`--ui`）

> v0.1.0 にはありません。次のリリースまでは、ソースからビルドして使ってください。

`reqcove run --ui` は、tailnet のノードに、記録を見るための読むだけのページを出し、そのリンクを QR コードで表示します。iPhone のカメラで読むと、Safari で一覧が開きます。一覧は 1 秒ごとに新しい記録を追います。Split View で、アプリと並べても使えます。記録を押すと、ヘッダーと本文が見られます（MCP の道具と同じく、マスク済みです）。

- 検索：URL とヘッダーを、打つそばから絞り込みます。「bodies too」を入れると、残している本文の先頭も探します（全部の記録をなめるので、そのあいだ一覧は新しい記録を追いません）。ステータス（2xx〜5xx、応答なし）や、ホスト（記録のページから）でも絞れます。
- Clear：それまでの記録を一覧から隠し、これから来る分だけを見られます。「Show all」で戻ります。消すわけではなく、エージェントからは今までどおり見えます。
- Live / Paused：新しい記録を追うのを、止めたり再開したりします。下にスクロールしている間は一覧を動かさず、新しい記録の数だけを出します。押すと表示します。
- iPhone のカメラから開けることは試しました。この画面、検索、Clear を iPhone で使うのは、まだ試していません（テストでは、ページのスクリプトを node で動かして確かめています）。

- tailnet にある自分の端末（自分のアカウントでログインしている iPhone、サブ機の MacBook、iPad など）なら開けて、全端末の記録が見えます。`--device` に入れた他人の端末は、その端末自身の記録だけです。それ以外の端末は入れません。読めるのは、リンクを開いたブラウザだけです。リンクは起動のたびに同じです（トークンは状態のフォルダの `ui-token` に保存されます。変えるには、それを消して起動し直してください）。一度開いた端末には Cookie が 400 日残るので、起動し直してもブックマークから開けるはずです（Cookie はテストで確かめました。iPhone の Safari で起動し直すのは、まだ試していません）。
- Tailscale はオンにしておく必要があります。Exit Node でも Remote Proxy でも、どちらも使っていなくても開けます。このページを見る通信は、記録されません。

## iOS シミュレーター（`--local-proxy`）

> v0.1.0 にはありません。次のリリースまでは、ソースからビルドして使ってください。

```sh
reqcove run --allow-hosts api.example.com --local-proxy   # iPhone も記録するなら --device も
```

シミュレーターのアプリは、このコンピュータのネットワークを使うので、Exit Node では運べません。`--local-proxy` を付けると、代わりに `127.0.0.1:8082` に HTTP プロキシを開き、そこを通ったリクエストを `local` という端末として記録します。macOS では、Charles や Proxyman と同じように、`run` がシステムの Web プロキシ（HTTP と HTTPS、有効なネットワークサービスすべて）をそこへ向け、止まるときに元へ戻します。異常終了したときは、次の起動か `reqcove cleanup` で戻ります。起動しているシミュレーターには、Reqcove の CA も入れます（`xcrun simctl keychain … add-root-cert`）。あとから起動したシミュレーターには、表示されるコマンドで入れてください。Linux では何も書き換えません。アプリをプロキシに向け（`HTTPS_PROXY=http://127.0.0.1:8082`）、CA を信頼させてください。

- シミュレーターだけでなく、このコンピュータのアプリ全部が、このプロキシを通るようになります。復号して記録するのは `--allow-hosts` のホストだけですが、そのホストは、Reqcove の CA を信頼していないこのコンピュータのアプリ（Mac の Safari など）では、つながらなくなります。
- このコンピュータ、LAN、tailnet（`*.ts.net` も）、`*.local` は、プロキシの例外に足すので、今までどおり直接つながります（例外でのアドレスの書き方は、まだ試していません）。名前は、このコンピュータと同じやり方で引きます（VPN、split DNS、検索ドメインも効きます）。`--dns` は使いません。LAN、VPN、tailnet に着く名前は、そのまま通します。このコンピュータ自身やリンクローカルのアドレスに着く名前は、このコンピュータの `/etc/hosts` が与えるものでなければ断ります。サイトが自分の名前を 127.0.0.1 に向けても（DNS rebinding）、プロキシ越しにこのコンピュータのサービスへは届きません。
- `run` が動いている間、システムのプロキシは reqcove のものになります。Ctrl-C、`kill`、ターミナルを閉じたときは元に戻ります。reqcove を強制終了したとき（`kill -9`）や落ちたときは、システムのプロキシを使うアプリが、次の `run` か `reqcove cleanup` で戻るまで（またはシステム設定で自分で戻すまで）つながりません。
- このコンピュータ自身のブラウザ：許可したホストへのリクエストを、警告で止めるのではなく、復号して記録したいときは（記録の上では `local` として、シミュレーターの通信と混ざります）、このコンピュータに Reqcove の CA を一度信頼させてください。まだ信頼していなければ、`run` がコマンドを表示します。やめ方は `reqcove status` と `reqcove cleanup` が表示します。macOS 27 で試しました（コマンド、Reqcove による信頼の確かめ、やめ方の表示、Mac の Chrome で許可したホストが警告なしに開けて記録されること）。Linux では試していません。
  - macOS（HTTPS だけを信頼。パスワードを聞かれます）：`security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem`。Firefox は、自分の証明書ストアを使うことがあります。やめるときは、`reqcove status` が出すコマンドを実行するか、キーチェーンアクセスで CA を削除してください（信頼の設定も一緒に消えます。試しました）。
  - Linux：Debian と Ubuntu は `sudo cp ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/reqcove.crt && sudo update-ca-certificates`。Fedora は `/etc/pki/ca-trust/source/anchors/` に置いて `sudo update-ca-trust`。Chrome と Chromium は `certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n Reqcove -i ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem`。Node は `NODE_EXTRA_CA_CERTS=` にそのファイルを。Python は、更新したシステムの証明書の束を指してください（そのファイルだけを指すと、ほかの CA が全部使えなくなります）。
- 自動プロキシ構成（PAC）と、認証付きのプロキシは、そのままにします。それらがある環境では試していません。本物の `networksetup` とシミュレーターでも、まだ試していません（テストは代わりのプログラムで確かめています）。

## HAR ファイルに書き出す

> v0.1.0 にはありません。次のリリースまでは、ソースからビルドして使ってください。

`reqcove run` が動いている間に `reqcove har > flows.har` を実行すると、記録を HAR 1.2 のファイルに、古い順で書き出します。デフォルトは新しい 1000 件までです（`--limit 0` で全部）。`--host`、`--device`、`--since 10m`、`--until`、`--status 4xx`、`--method`（v0.1.0 のあとは `--user-agent` も）で絞り込めます。中身は MCP の道具が返すものと同じです。受け取った時点でマスク済みで、本文は先頭だけです（切れた本文は、コメントにそう書きます）。マスクで確かめられなかった本文は入りません。`run --no-redact` のときは何もマスクされず、ファイルのコメントにそう書きます。HAR 1.2 の仕様の必須の項目に沿って書いています（仕様を読んで書いたもので、検証ツールにはかけていません）が、ほかのツール（ブラウザの開発者ツール、Charles、Proxyman）で開くのは、まだ試していません。

## Web アプリのバックエンド（Rails など）

> v0.1.0 にはありません。次のリリースまでは、ソースからビルドしてください。

Web アプリが自分でほかの API を呼ぶ通信（Rails のサーバーが決済の API を呼ぶ、など）は、iPhone ではなくサーバーから出ます。Reqcove に見えるのは、サーバーがその通信を Reqcove に通し、Reqcove の CA を信頼しているときだけです。tailnet にある自分のマシンで動くサーバーなら、そのマシンを `--device` に入れ、サーバーにノードの Remote Proxy を指定します。

```sh
reqcove run --device dev-server --allow-hosts api.example.com
# dev-server で：変数は両方（Ruby の Net::HTTP は HTTPS でも http_proxy を見る）、
# CA の束には Reqcove の CA を足す（システムの束と mitmproxy-ca-cert.pem をつなぐ）
http_proxy=http://100.x.y.z:8080 https_proxy=http://100.x.y.z:8080 SSL_CERT_FILE=bundle.pem bin/rails server
```

- 記録は、そのマシンの名前で残ります。マシンの設定は変えず、サーバーの環境変数だけで済みます。
- データベースや Redis への接続は、80 番と 443 番の HTTP(S) ではないので見えません。
- ブラウザからアプリへのリクエストは別の道です。iPhone からなら、許可したホストへのリクエストを `map_remote` で開発サーバーに送ります（[ルール](#ルール)）。
- この Mac を端末にして、Ruby の Net::HTTP で試しました。CA がないと Ruby は証明書を拒み（TLS の失敗が記録された）、CA があると呼び出しが記録されました。Rails のアプリそのもの、Faraday などほかのクライアント、別のマシンのサーバーでは試していません。

## 上流のプロキシ（Burp Suite など）

> v0.1.0 にはありません。次のリリースまでは、ソースからビルドして使ってください。

Reqcove の記録を残したまま、同じリクエストを Burp Suite（や ZAP、Charles など）でも見るには、そちらに回します。

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' \
  --upstream-proxy http://127.0.0.1:8080
```

- 復号したリクエストは、プロキシを通ります（HTTPS は CONNECT のトンネルで、平文の HTTP はプロキシのリクエストとして）。本物のサーバーへ直接つなぐことはありません。`--allow-hosts` の外のホストへの接続は、今までどおり直接通ります。ただし、許可したホストへの復号した接続に相乗りした、ほかのホスト宛てのリクエスト（HTTP/2 の接続の使い回し）も、記録はしませんが、プロキシを通ります。Burp の Intercept はオフにしてください。オンだと、リクエストがそこで止まります。
- Reqcove は、iPhone がつないだアドレス（IP）をプロキシに渡します。ただ、Burp は HTTPS では、SNI の名前をこのコンピュータで引き直して、そちらにつなぎます（試して確かめました）。そのため、Exit Node が「このコンピュータと LAN は宛先にしない」と拒んでいても、Burp のつなぐ先には効きません。しかも、iPhone で開いたサイトが、その引き直しにこのコンピュータや LAN のアドレスを返すこともできます（DNS rebinding。コードを読んで考えたことで、試してはいません）。`--allow-hosts` は、試すホストだけにしてください（`'*'` のときは、`run` が警告を出します）。同じ理由で、`resolve` のルールは `--upstream-proxy` と一緒には使えません。プロキシ自身の設定（Burp の Hostname resolution overrides）を使ってください。平文の HTTP は、Burp では IP で表示され、名前は `Host` ヘッダーで分かります。
- プロキシを通る HTTPS は、プロキシの CA だけで確かめます。このコンピュータで動いていて、Burp のように `http://burp/cert` で CA を配るプロキシなら、起動のときに自動で取ってきます。ほかの、自分で復号するプロキシ（ZAP、Charles など）は、`--upstream-ca FILE`（PEM か DER）で CA を渡してください。どちらでもなければ、公開の CA で確かめます（自分では復号しないプロキシ向け）。
- Reqcove はプロキシに自分で直接つなぎ、システムのプロキシの設定は見ません。ただ、起動するとシステムのプロキシを自分に向けるプロキシ（Charles は、Proxy メニューの「macOS Proxy」を切らない限りそうします）と `--local-proxy`（v0.1.0 のあとに追加）は、同じ設定を取り合い、止めるときには相手の設定へ戻してしまいます。`--local-proxy` と一緒に使うときは、プロキシの側のその動きを切ってください。Charles では試していません。
- プロキシを通るのは HTTP(S) だけです。許可したホストへの、ほかのプロトコル（MQTT など）は、本物のサーバーへ直接つながります（コードを読んで確かめたこと）。TLS の上のものは、プロキシの CA を使っているとき（`--upstream-ca` で渡したときも、Burp の CA を自動で取ってきたときも）、サーバーの証明書をその CA で確かめることになるので、失敗します。また、サーバーの名前（SNI）を送らない、IP アドレスへの HTTPS は、Burp を通すと失敗します。Burp が、そのアドレスを mitmproxy の受け付けない形で証明書に入れるためです。
- プロキシは、マスクしていない中身を全部見ます。Burp は、それをプロジェクトに残します。Burp Suite Community 2026.10 で試しました。ほかのプロキシは試していません。Burp で見えたこと：リクエストの本文は、全部届くまで Burp が溜めます。HTTP/1.1 のクライアントへの SSE（サーバーから流すイベント）は失敗します（iOS のアプリの多くが使う HTTP/2 なら流れます）。`--web` と一緒に使うと、mitmweb から平文の HTTP のリクエストを送り直したときに、プロキシ自身に送られます。

## 証明書ピンニング

> v0.1.0 にはありません。次のリリースまでは、ソースからビルドしてください。

証明書をピンニングしているアプリは、Reqcove の証明書を拒むので、そのホストへのリクエストは失敗します。`reqcove status` がそのホストを、`run` に付ける `--pass-hosts` と一緒に示します。付けて起動し直すと、そのホストは復号せずに通り、アプリが動きます（iPhone で試しました）。

```sh
reqcove run --device iphone --allow-hosts '*' --pass-hosts '*.example-cdn.com,api.example.com'
reqcove run --device iphone --allow-hosts '*' --pass-hosts @pass-hosts.txt   # 1 行に 1 ホスト
```

- そのホストは、接続だけを記録します（ホスト、宛先、時刻、量：`list_passthrough`）。URL や中身はありません。
- `--rules` と `--upstream-proxy` は効きません。
- TLS が終わってから確かめるピンニングは、どこにも出ません。
- 自分のアプリなら、ピンニングを外したビルドを使ってください。
- iOS では、Flutter（`dart:io`）や React Native で作られたアプリも、ほかのアプリと同じく Reqcove の CA を信頼しました（iPhone で試しました）。
- Android では、アプリはシステムの CA しか信頼せず、自分で入れた CA は信頼しません。CA を入れたあと、Chrome は復号でき、ほかのアプリはすべて拒みました（Android 14 の端末で試しました）。Android の端末なら、`reqcove status` がそう案内します（Tailscale が知らせる OS から判断）。`--allow-hosts` は調べたいホストに絞ってください。それ以外のホストは復号せずに通すので、アプリは動きます。自分のアプリなら、デバッグ用のビルドで、`network_security_config` に自分で入れた CA を信頼すると書きます。サンプルのアプリで、書いたホストは復号でき、書いていないホストは CA を拒むことを確かめました。

  ```xml
  <network-security-config>
    <debug-overrides>
      <trust-anchors>
        <certificates src="user" />
      </trust-anchors>
    </debug-overrides>
  </network-security-config>
  ```

  （サンプルはホストを `domain-config` で指定しました。デバッグ用のビルドだけに効く `debug-overrides` の形は試していません。）


## そのほかの制限事項

- IPv6 は拒否します（アプリはすぐに IPv4 にフォールバックします）。QUIC は Apple 宛て以外をドロップするので、アプリは TCP にフォールバックします。見分けるのはアドレスで、ホストではありません。そのため、`--allow-hosts` に入っていないホストの QUIC も（`--allow-hosts` がないときも）TCP に切り替わります。443 以外のポートを使う QUIC は止めずにそのまま通し、記録もしません。
- Exit Node 経由の通話は試していません。
- mitmweb（`--web`）では、mitmproxy の設定を変えられます。Capture のタブの「Run SOCKS Proxy」は、オンのままにしてください。Reqcove がデバイスの通信を mitmproxy に渡す入り口で、外すとデバイスの HTTP(S) がつながらなくなります。そこにあるほかのモードは、Reqcove では使いません。変えた設定は reqcove を起動し直すと戻り、Reqcove の記録の範囲とマスクは崩れません（コードを読んで考えたことで、試してはいません）。
- Reqcove を動かしているコンピュータの iOS シミュレーターには、`--local-proxy` が要ります（上を参照。v0.1.0 のあとに追加）。別の Mac を `--device` に入れ、その Mac で Reqcove の Exit Node を使えば（[手順](another-mac.ja.md)）、シミュレーターの通信も、その Mac の通信と一緒に通るはずです。シミュレーターに Reqcove の CA を入れる必要があります（試していません）。
- mitmproxy は WebSocket のメッセージを、届ききるまで1つずつ溜めます。巨大なメッセージが来るとメモリを多く使います（mitmproxy が落ちたら、reqcove が起動し直します。起動し直しても 1 分以内に落ちるのが 5 回続くと、`run` が止まります）。
- `map_local` が答えるのは、ボディが 1 MiB 以下で長さが分かっているリクエストだけです。それ以外は本来の宛先へ送ります（記録にその旨が残ります）。長さのない HTTP/2 の GET には答えるので、そこにデバイスがボディを付けて送ってくると、まるごと溜めます。こうしたリクエストを送るのは、自分のデバイスだけです。

## Tips

- 新しいノードのたびに Exit Node を承認する手間を省くには、tailnet のポリシーに自動承認を追加します：`"autoApprovers": {"exitNode": ["you@example.com"]}`
- 状態ディレクトリが同じであれば、CA も同じままです。2 台のコンピュータで 1 つの CA を使うには、`~/.reqcove/mitmproxy/` をディレクトリごと、もう 1 台の `~/.reqcove/` にコピーします（秘密鍵が含まれます）。もう 1 台の reqcove は止めておいてください（v0.1.0 のあとは、初めて起動する前でもかまいません）。
