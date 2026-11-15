# Reqcove ガイド

[English](guide.md) · [README](../README.ja.md)

README の 4 つの手順を終えたあとに読むガイドです。各節の最後に、試したことと試していないことを「確認状況」として短く書いています。確認状況に出てくる mitmproxy は 12.3.1（Reqcove がロックしているバージョン）、Linux は Ubuntu 24.04（arm64）です。E2E テストは本物の mitmproxy を動かすテストです。

各節ではいちばん大事な注意を手順のそばに書いています。オプションごとのそのほかのセキュリティの注意は、その節の「セキュリティの詳細」に折りたたんであります（クリックすると開きます）。テストや実機で確かめたことは、そこの「確認状況」に書いています。要点と、「状態ディレクトリ」「あなた自身のデバイス」という言葉の意味は、[SECURITY.ja.md](SECURITY.ja.md) を見てください。「セキュリティの詳細」に書いているのは、SECURITY.ja.md に書いていないことだけです。

1. [セットアップする](#セットアップする)：[初回の起動](#初回の起動ログインと承認) · [停止・再起動・アップデート](#停止再起動アップデート) · [2 台で同じ CA](#2-台のコンピュータで同じ-ca-を使う) · [元に戻す](#元に戻すreqcove-cleanup)
2. [エージェントに通信を読ませる](#エージェントに通信を読ませる)：[ツールを許可する](#ツールを許可する) · [Skill](#使い方を教える-skill-を入れるreqcove-init) · [マーカー](#マーカーを置くreqcove-mark) · [ほかのデバイスのエージェント](#ほかのデバイスのエージェントから使う--mcp-http)
3. [自分でフローを見る](#自分でフローを見る)：[iPhone で](#iphone-で見る--ui) · [HAR ファイルで](#har-ファイルに書き出すreqcove-har) · [mitmweb で](#mitmweb-で見る--web)
4. [iPhone アプリ以外のクライアントを記録する](#iphone-アプリ以外のクライアントを記録する)：[証明書ピンニングをするアプリ](#証明書ピンニングをするアプリを通す--pass-hosts) · [HTTP として読まれない接続](#http-として読まれない接続raw-tcp) · [gRPC](#grpc) · [Android](#android-を記録する) · [iOS シミュレーター](#ios-シミュレーターを記録する--local-proxy) · [Web アプリのバックエンド](#web-アプリのバックエンドを記録する) · [Wi-Fi のプロキシ](#exit-node-を使わずに-wi-fi-のプロキシでつなぐ) · [別の Mac](#別の-mac-を記録する)
5. [リクエストの行き先を変える](#リクエストの行き先を変える)：[ルール](#ルールを書く--rules) · [モック](#ここで応答するmock) · [プリセット](#エージェントが有効にできるプリセット) · [ルールが当たった理由](#ルールが当たった理由当たらなかった理由list_rulesexplain_rules) · [上流プロキシ](#上流プロキシに回す--upstream-proxy)
6. [Tailscale を使わずに同じネットワークでつなぐ（LAN モード）](#tailscale-を使わずに同じネットワークでつなぐ--lan)
7. [サービスとして動かす](#サービスとして動かす)：[`brew services`](#常駐させるbrew-services) · [`reqcove service install`](#homebrew-なしで常駐させるreqcove-service-install)
8. [コンテナで動かす](#コンテナで動かす)
9. [うまくいかないとき](#うまくいかないとき)
10. リファレンス：[オプション](#オプション) · [MCP ツール](#mcp-ツール) · [制限事項](#制限事項) · [セキュリティ](#セキュリティ) · [互換性](COMPATIBILITY.ja.md)

## セットアップする

インストールは [README](../README.ja.md#インストール) にあります。初回の 4 つの手順も README にあります（[使い方](../README.ja.md#使い方)）。

### 初回の起動：ログインと承認

`reqcove setup` をターミナルで実行すると、初回の手順を順に案内します。エージェントから実行したときのように、入力か出力がターミナルでなければ断ります。どの手順も空の答えで飛ばせます。setup は何も起動せず、何も消しません。

- uv：`uvx` の場所を示すか、入れ方を表示します。uv を入れることはしません。
- デバイスとホスト：`--device` と `--allow-hosts` を引用符付きで、サービスが読むファイルに書きます。
  - ファイルは `~/.config/reqcove/config`（`reqcove service install` が読むもの）です。Homebrew で入れた場合（このバイナリが `Cellar/reqcove/` の下にあるとき）は、Homebrew の `$(brew --prefix)/etc/reqcove/config`（`brew services` が読むもの）です。
  - ファイルのパーミッションは 0600（自分だけが読み書きできる）で、ディレクトリを新しく作るときは 0700 です。ファイルを置き換える前に、`run` と同じ読み方で確かめます。
  - `*` と、`-` で始まる名前は聞き直します。URL を貼り付けた場合はホストだけを書きます。
  - ホストがまだ決まっていなければ、`run` が動き始めてから `reqcove status`（またはエージェントの `summarize`）で iPhone がつないだホストを確認できます。
  - ファイルがすでにあれば表示し、`y` と答えない限りそのまま残します。`y` なら全体を置き換え、元のファイルは `config.old`（0600）として残します。`--rules` などほかのフラグはそこから書き戻せます。
  - 普通のファイルでないものは触りません。
- エージェント：`y` と答えれば、`reqcove init` と同じように Skill を入れます（ホームディレクトリにエージェントが見つからないときは、そう表示します）。`claude mcp add reqcove -- reqcove mcp` を表示し、エージェントのコマンドは実行しません。`PATH` の `reqcove` がないか、このバイナリとは別のものであるときは、表示するコマンドでこのバイナリをフルパスで書きます（`service install` の表示も同じです）。
- 起動のしかた：Homebrew で入れた場合は `brew services start reqcove`、それ以外は `reqcove service install`、またはターミナルで `reqcove run --config FILE` です。`--lan` はファイルに書けないので、ターミナルで `reqcove run --lan --allow-hosts HOSTS` を実行します。ログイン用の URL は表示しません（`reqcove links` が表示します）。
- Ctrl-C を押すと、その質問のところで止まります。それまでに書いたものは残ります。

残っている手順は `run` が表示し、`reqcove status` でも確認できます。

1. 表示された URL でログインします。
2. tailnet が Tailnet Lock を使っていれば、ノードに署名します。
3. Exit Node を承認します。

ログイン用の URL とリンクの扱いは次のとおりです。

- ログイン用の URL を最初に開いた人の tailnet に、ノードが入ります。トークンを含む `--ui`、`--web`、`--mcp-http` のリンクも、ログイン用の URL と同じように扱います。`run` はどちらもターミナルにだけ表示します（[SECURITY](SECURITY.ja.md#ログイン用の-url)）。
- もう一度表示する：自分のターミナルで `reqcove links` を実行します。QR コード付きで表示し、このコンピュータで開く mitmweb のリンクと CA のリンクも表示します。出力先がターミナルでなければ断ります（Claude Code の `!` からも表示されません）。
- サービスや `docker logs` のようにターミナルでないところでは、`run` はその代わりに「`reqcove links` prints it」と表示します。
- 承認を省く：新しいノードのたびに Exit Node を承認する手間を省くには、tailnet のポリシーに自動承認を追加します（`"autoApprovers": {"exitNode": ["you@example.com"]}`）。

確認状況（`reqcove setup`）：単体テスト（答えを流し込んで実行）と、macOS と Linux（VM に ssh で接続）での手作業（2026-11-14）で確かめました。最初の質問で Ctrl-C を押すこと（すぐに終わり、何も書かれませんでした）と、Claude Code の `!` から `reqcove links` を実行することも試しました。試していないもの：setup が書いたファイルでの `brew services`。

<a id="security-login-url"></a>

<details>
<summary>セキュリティの詳細：ログイン用の URL とリンクを、ログとファイルに残さない仕組み</summary>

表示される場所と、ファイルを読める人は、[SECURITY](SECURITY.ja.md#ログイン用の-url) にあります。そのほかの点は次のとおりです。

- **ターミナルでないところ**（サービス、`-t` なしの `docker logs`、エージェントのシェル）では、`run` は URL もリンクも表示しません。`reqcove links` で表示できることだけを伝えます。
- Skill とサーバーの instructions はエージェントに、`reqcove links` を実行しないよう伝えています。
- `run` がログに出す行と、終了時のエラーは、すべて 1 つのフィルターを通ります。フィルターは、トークン、`run` がすでに見たログイン用の URL、コントロールサーバーのログイン用の URL の形をした URL（Tailscale の `/a/<hex>`、Headscale の `/register/…` と `/register?key=…`）を置き換えます。`--verbose` のときは、tsnet 自身の行も対象です。tsnet は、`run` が URL を知る前に URL を出力するからです。
- フィルターが知っている形はこれだけです。ほかの形のログイン用の URL は、`run` が最初にポーリングしたとき（3 秒以内）からマスクします。
- **`login-url` と `links`** は状態ディレクトリに 0600 のファイルとして保存し、`run` の起動時と終了時に削除します。クラッシュしたあとは次の起動まで残ります。`reqcove links` は、`run` が動いているかどうかを確かめないからです。
- tsnet は自分の行を、状態ディレクトリにあるバッファのファイルに保存します。ログイン用の URL もそこに入ります（`tsnet/tailscaled.log*.txt`、0600）。`--verbose` を付けないときも同じです（コードから判断したものです）。
- mitmweb のサーバーは失敗したリクエストの URL を `mitmproxy.log` に書きます。URL には `?token=` も含まれますが、アドオンが先にトークンをマスクします。

確認状況：テスト（テスト用のコントロールサーバーから tsnet の行を読むテストと、mitmweb の E2E テストでの `mitmproxy.log` の確認）。Claude Code の `!` で `reqcove links` を実行しても何も出ないことを試しました（2026-11-13）。

</details>

### 停止・再起動・アップデート

- 停止：Ctrl-C で止めます。記録はメモリにあるので、一緒に消えます。そのあと iPhone の DNS が止まったままになったら（[tailscale#20870](https://github.com/tailscale/tailscale/issues/20870)）、Exit Node を一度オフにして、オンに戻してください。
- 再起動：`run` が止まっている間も `reqcove mcp` は動き続け、ツールは「動いていない」と答えます。`run` が戻れば、エージェントを再接続（Claude Code の `/mcp`）しなくても使えます。記録は空から始まり、最初の答えが `note` でそう伝えます。
- アップデート（`brew upgrade reqcove` や、ソースからのビルドで新しいバージョンを入れたとき）：新しい reqcove で `run` を起動し直し、エージェントを一度再接続します。新しいツールを使うためで、バージョンが違う間はツールがそう伝えます。Skill も新しくするため、`reqcove init` をもう一度実行します。

確認状況：Claude Code のセッション中に `run` を再起動して確認しました。

### 2 台のコンピュータで同じ CA を使う

状態ディレクトリが同じであれば、CA も同じままです。秘密鍵を含む `~/.reqcove/mitmproxy/` をディレクトリごと、もう 1 台の `~/.reqcove/` にコピーします。コピー先の reqcove は止めておくか、初めて起動する前にコピーしてください。

コピーにも鍵が入ります。どちらかのディレクトリを持つ人は、iPhone に対してどの HTTPS サイトにもなりすませます。どちらのディレクトリも自分だけのものにしておいてください（[SECURITY](SECURITY.ja.md#ca-の秘密鍵)）。

<a id="security-ca-copies"></a>

<details>
<summary>セキュリティの詳細：Reqcove が作る CA のコピーと、バックアップ</summary>

鍵でできることと、コピーやバックアップの扱い方は、[SECURITY](SECURITY.ja.md#ca-の秘密鍵) にあります。そのほかの点は次のとおりです。

ほかの状態ディレクトリにあるコピーには、次の点があります。

- `--state` で指定したディレクトリに CA がないときは、そのディレクトリが起動時に `~/.reqcove` の CA のコピーを受け取ります。そのため、1 台のコンピュータで複数の Exit Node を動かしても、iPhone のプロファイルは 1 つで済みます。コピーするのは鍵の入った `mitmproxy-ca.pem` と証明書のファイルです。`mitmproxy-ca.p12` と mitmweb のパスワードはコピーしません。コピーした先は `run` がログに出します。
- 鍵はそのディレクトリのそれぞれに入ります。どのディレクトリも 0700 で、ファイルは 0600 です。1 つを削除しても、ほかのディレクトリに鍵が残ります。[SECURITY](SECURITY.ja.md#ca-の秘密鍵) の「ディレクトリを削除します」は、そのすべてを削除するという意味です。すべてを止めるには iPhone からプロファイルを削除します。
- コピーの一覧は `~/.reqcove/ca-copies` にあります。`~/.reqcove` に対する `cleanup` はまだ CA を持っているディレクトリを挙げます。コピーに対する `cleanup` は、プロファイルが両方に使われていることを伝えます。
- どのコマンドも `~` で始まる `--state` を断ります。`--state=~/x` はシェルが展開しないので、鍵が `./~/x` に置かれ、`cleanup` が本物のディレクトリを「ない」と報告してしまうからです。

バックアップには、次の点があります。

- バックアップにも鍵が入ります。状態ディレクトリはホームにある普通のディレクトリで、Reqcove はその中のものにバックアップ対象外の印を付けません（コードから判断したもので、バックアップの中身は見ていません）。Time Machine や、ホームを対象にするほかのバックアップや同期のツールは、CA の鍵、ノードの鍵（`tsnet/`）、トークンをコピーし、`cleanup --delete-state` のあとも持ち続けます。
- バックアップから復元すると、ファイルのモードが広がり、このコンピュータのほかのユーザーも読めるようになることがあります。`run` は起動時に、ディレクトリを 0700 に、トークンのファイルを 0600 に戻します。ほかのファイルは戻しません（コードから判断したものです）。

確認状況：テスト（コピーのディレクトリが 0700、ファイルが 0600 であること）。

</details>

### 元に戻す（`reqcove cleanup`）

`reqcove cleanup` が手順を表示します。`--delete-state` を付けると、状態ディレクトリを削除します。先に次のことをしてください。

- iPhone から CA のプロファイルを削除します（[SECURITY](SECURITY.ja.md#ca-の秘密鍵)）。
- サービスを止めます（`brew services stop reqcove` か `reqcove service uninstall`）。止めないと、サービスは次のログインで `run` をまた起動し、状態ディレクトリを作り直します。

cleanup が削除しないもの（tailnet のノード、サービスのファイル、Skill、HAR ファイル、バックアップ、エージェントの会話の記録）は、[下の「セキュリティの詳細」](#security-cleanup)にあります。

<a id="security-cleanup"></a>

<details>
<summary>セキュリティの詳細：cleanup のあとに残るものと、それぞれの取り除き方</summary>

cleanup が自分で行うことと、状態ディレクトリの削除を断る場合は、[SECURITY](SECURITY.ja.md#reqcove-cleanup-のあとに残るもの) にあります。

次のものは、あなたが取り除くまで残ります。

- **各デバイスの CA のプロファイルと、このコンピュータやシミュレーターでの CA の信頼。** cleanup は iPhone、シミュレーター、Mac のキーチェーンについて方法を表示しますが、どれも自分では行いません。ほかの場所に足した信頼（Linux の証明書ストア、ブラウザ独自のストア、Android）は、cleanup には分かりません。
- **tailnet のノード**（管理コンソールの Machines）と、スマートフォンで選んだ Exit Node や Wi-Fi プロキシ。
- **ほかの状態ディレクトリ**（`--state`）。クリーンアップはディレクトリごとに行います。`~/.reqcove` に対する cleanup が挙げるのは、その CA のコピーを持つディレクトリだけです。
- **サービス。** cleanup はサービスに触れません。`reqcove service uninstall` はサービスを止めてそのファイルを削除しますが、フラグのファイル（`~/.config/reqcove/config`）は残します。`brew services stop reqcove` は Homebrew のサービスを止めますが、そのフラグのファイルとログ（`$(brew --prefix)/var/log/reqcove.log`）は残ります。サービスを残しておくと、次のログインで `run` が起動し、状態ディレクトリと新しい CA を作り直します。
- **Skill**（`reqcove init --uninstall` で削除します）と、エージェントの MCP サーバーの登録。
- **Reqcove の外に出たもの。** HAR ファイル、エージェントの会話の記録（[SECURITY](SECURITY.ja.md#エージェントが読んだものの行き先)）、バックアップ、uv のキャッシュにある mitmproxy と Python です。

確認状況：テスト（削除を断る場合、プロキシを元に戻すこと、CA のコピーを持つディレクトリを挙げること）。

</details>

## エージェントに通信を読ませる

`claude mcp add reqcove -- reqcove mcp`（README の手順 4）を実行すると、このコンピュータのエージェントが [MCP ツール](#mcp-ツール)を使えるようになります。Codex なら `codex mcp add reqcove -- reqcove mcp` です。`run` が両方を表示します。

ツールにできることは次のとおりです。

- 読む：シークレットは届いた時点でマスクされます（[マスクで見つけられないもの](SECURITY.ja.md#マスク)）。
- プリセットを有効にする：ツールにできる変更はこれだけです。[プリセット](#エージェントが有効にできるプリセット)はあなたがプリセットにしたルールです。モックか、リクエストの中身や行き先を変える `map_remote`、`modify_headers`、`resolve` のルールです。有効になるのは 1 回につき最長 5 分で、何度でも有効にし直せます。プリセットがなければ、ツールは読むだけです。`--mcp-http` からは有効にできません。
- [マーカー](#マーカーを置くreqcove-mark)を置く：デバイスの側は何も変わりません。

### ツールを許可する

- 読むツールには読み取り専用の注釈（`readOnlyHint`）を付けています。クライアントはこれを使って確認を減らせます（どのクライアントでも確かめていません）。
- 読み取り専用の注釈を付けていないもの：プリセットを有効・無効にするツール（`activate_preset`、`deactivate_preset`）と、`add_marker`（書き込むのは Reqcove のメモリだけ）です。
- Claude Code は許可していないツールを使う前に確認します。読むツールは名前で許可してください（`"mcp__reqcove__list_flows"` など）。`"mcp__reqcove"` でまとめて許可すると、読み取り専用の注釈のないツールも許可されます（プリセットに書いたサーバーへリクエストを送れる `activate_preset`）。Claude Code のドキュメントによるもので、ここでは試していません。

たとえば `.claude/settings.json` に次のように書きます（書き方は Claude Code のドキュメントによるもので、ここでは試していません）。

```json
{
  "permissions": {
    "allow": ["mcp__reqcove__status", "mcp__reqcove__summarize", "mcp__reqcove__list_flows",
              "mcp__reqcove__search_flows", "mcp__reqcove__wait_for_flows", "mcp__reqcove__get_flow",
              "mcp__reqcove__list_ws_messages", "mcp__reqcove__diff_flows", "mcp__reqcove__list_tls_failures",
              "mcp__reqcove__list_passthrough", "mcp__reqcove__list_devices", "mcp__reqcove__capture_stats",
              "mcp__reqcove__list_presets", "mcp__reqcove__list_rules", "mcp__reqcove__explain_rules",
              "mcp__reqcove__list_markers", "mcp__reqcove__add_marker"],
    "ask": ["mcp__reqcove__activate_preset", "mcp__reqcove__deactivate_preset"]
  }
}
```

v1.0 より前に書いたリストには、`mcp__reqcove__list_mock_presets`、`mcp__reqcove__activate_mock`、`mcp__reqcove__deactivate_mock` が入っていることがあります。これらのツールはもうありません。`mcp__reqcove__list_presets`、`mcp__reqcove__activate_preset`、`mcp__reqcove__deactivate_preset` に置き換えてください。`activate_preset` はモックだけでなくほかの種類も有効にするので、例では `activate_preset` と `deactivate_preset` を `ask` に置いています。一緒に名前が変わったフィールド（スクリプトで読むもの）と、削除したツールを呼んだときの答えは、[互換性](COMPATIBILITY.ja.md#mcp-ツール)にあります。

注意点は次のとおりです。

- Codex は呼び出しごとに確認します（[HTTP](#ほかのデバイスのエージェントから使う--mcp-http) でも）。
- 許可したあとは、`run` を `--no-redact` で起動していても、エージェントは確認なしで読みます。その場合も、Skill とサーバーの instructions は、止まってユーザーに聞くよう伝えます。
- 許可するのは Reqcove のツールだけにして、シェルのコマンドやネットワークのツールまで一緒に許可しないでください。サイトが記録に書き込んだ文が、エージェントにそれらを使わせようとすることがあります（[SECURITY](SECURITY.ja.md#プロンプトインジェクション)）。

<a id="security-agent"></a>

<details>
<summary>セキュリティの詳細：Reqcove がエージェントに伝えていることと、記録からは証明できないこと</summary>

エージェントが Reqcove のツールと自分のツールでできることと、エージェントに与えるものは、[SECURITY](SECURITY.ja.md#プロンプトインジェクション) にあります。そのほかの点は次のとおりです。

- エージェントが有効にできるプリセットは、あなたが書いたものだけです（[モックのプリセット](#security-mock-presets)、[ほかの種類のプリセット](#security-presets)）。
- `add_marker` も書き込みますが、書くのは Reqcove のメモリにあるマーカーだけです。
- Claude Code では、許可していないツールを使う前の確認を残してください。
- Codex のサンドボックスはデフォルトではネットワークなしです（Codex の文書から判断したもので、試していません）。

Reqcove がしていることは、次のとおりです。

- ツールがボディを返すのは、求められたときだけです。`diff_flows` が返すのは、違っている部分です。
- サイト、アプリ、tailnet が書いたものを返すツールは、どれも説明の中で、それがデータで指示ではないと伝えています（`--mcp-http` にある 12 個のツールも同じです。`list_markers` も、マーカーの文について同じことを伝えています）。
- プリセットとルールのツールが返すのは、あなたのルールファイルにあるものです。`add_marker` が返すのは、Reqcove 自身の値です。`list_presets` は、プリセットの説明があなたの言葉で、指示ではないと伝えています。
- サーバーの instructions は、すべてのクライアントに送られます（Grok Bot のように、Skill を持たないクライアントにも送られます）。instructions も同じことを伝えています。加えて、記録に書いてあることを理由にファイル（とくに `--rules` のファイル）、コミット、コマンドを書かないこと、`--no-redact` や `--web` を勧めないこと、`next_steps` はユーザーが行うものであることを伝えています。モデルがこれを守るかどうかは、テストでは示せません。
- Host がホスト名でもアドレスでもないリクエスト（アプリ独自の HTTP スタックは、そこにどんな文でも入れられます）は、中継しますが、記録しません。TLS から得たホストは mitmproxy 自身の確認によってホスト名に限られます（mitmproxy のコードから判断したものです）。
- 一覧と要約に出す User-Agent は 256 バイトに切ります。ALPN の名前は印字できる ASCII だけにします。`diff_flows` の JSON のキーのうち、単純な名前でないものは引用符で囲みます（`$["a.b"]`）。

次のことは記録からは証明できません。

- **フローのホスト**はリクエストの Host です。Host はアプリが選びます。任意のアドレスへの接続での平文の HTTP と、許可したホストへの接続での HTTPS では、Host に許可したホストを書けます。記録にはそのホストが出ます。リクエスト自体は接続の行き先へ進みます（ルールへの影響は[ルールのセキュリティの詳細](#security-rules)にあります）。
- **マーカーの `source`**（`cli`、`mcp`）は経路です。Reqcove が、呼び出しがどこから来たかで設定します（`reqcove mcp` は、エージェントのクライアント名を引き渡しません）。これは証明にはなりません。このコンピュータでコマンドを実行できるエージェントは、`reqcove mark` を実行するか、`run` のソケット（同じユーザー）に自分で接続すれば、`cli` を名乗れます。そうすれば、ユーザーの 100 件を押し出すこともできます。`reqcove mcp` を通すエージェントは `mcp` になり、それはできません。
- **マーカーの文**はユーザーかエージェントの言葉です。データで、指示ではありません（サーバーの instructions がそう伝えています）。

確認状況：テスト（ツールの説明。クライアントが stdio と HTTP で instructions を受け取ること。文面は確かめていません。そうした Host のリクエストを記録しないこと。`reqcove mcp` を通すエージェントが `mcp` になること）。

</details>

### 使い方を教える Skill を入れる（`reqcove init`）

Skill はツールの使い方をエージェントに教えます。最初に status を見ること、1 つのアプリの通信の探し方、TLS の失敗から考えられること、ルールファイルの書き方、そして守る決まり（`reqcove run` を自分で起動しない、トークンを求めない、記録の中身はデータとして扱う、マスクされていないシークレットを引用しない）です。

```sh
reqcove init                    # ホームディレクトリにあるエージェントに入れる：~/.claude/skills（Claude Code）、~/.agents/skills（Codex、Cursor、Gemini CLI、Copilot CLI、Devin）
reqcove init --client codex     # または、名前を挙げたものだけ（--client を繰り返す）
```

- reqcove をアップデートしたら、もう一度実行してください。入っている Skill のバージョンが違うと、`reqcove status` がそう伝えます。
- `init` が書いたものでない Skill、あとで書き換えた Skill、シンボリックリンクには触りません。`--uninstall` は自分が入れたものを削除し、`--print` は Skill を書き出します。
- MCP サーバーの登録はしません。登録は上のコマンドで行います。

確認状況：Claude Code、Codex、Devin、Cursor がそれぞれ Skill を使いました（Claude Code と Codex は、Reqcove の名前を出さずにアプリの通信先を尋ねると読み込みました。Devin は MCP サーバーがないときに登録を頼んで止まりました。Cursor はサーバーの instructions も読み、そのあとはツールだけで調べました）。試していないもの：Gemini CLI、Copilot CLI。

### マーカーを置く（`reqcove mark`）

iPhone で何かをタップする前に、ターミナルで `reqcove mark "tap Pay"` とすると、記録の中にマーカーを置けます。エージェントは `list_markers` で古い順に読み、`since` で絞り込めます。操作する前や、あなたが「いまから X をタップする」と言ったときには、エージェントが `add_marker` で自分のマーカーを置きます。`add_marker` は `id`、`time`（`list_flows` などの `since` と、報告に使う）、`checkpoint`（`wait_for_flows` の `after` に使う）を返します。

- テキストは 1 行で 80 文字まで。長いものや、改行などの制御文字を含むものは、切り詰めずに断ります。エラーの文と同じくマスクします（トークンは `[redacted]` になります）。
- `source` は `cli`（`reqcove mark`）か `mcp`（`reqcove mcp` を通したエージェント）です。経路を示すだけで、誰が置いたかの証拠ではありません。このコンピュータでコマンドを実行できるエージェントは、`cli` を名乗れます。`reqcove mark` を実行する（`reqcove lan` と同じく、断るのは入力か出力がターミナルでないときだけです）か、`run` のソケットに自分でつなぐかです。
- 置いた経路ごとに 100 個まで残し、古いものから消します。メモリにだけ置くので、フローの id と同じく、`run` を再起動すると消えます。`reqcove mcp` を通したエージェントは `mcp` になり、あなたのマーカーを押し出せません。上のように `cli` を名乗るエージェントは押し出せます。`--mcp-http` からは使えません。
- `add_marker` は書き込みのツールで、読み取り専用の注釈はありません。ただし、デバイスの側は何も変わりません。`reqcove mcp` は、接続が切れたあとに送り直しません。

確認状況：iPhone を使った確認の中で、Claude Code から `add_marker` を使いました（iOS 27.3、2026-11-14）。ほかはテストだけです（`reqcove mark` は手で試していません）。

### ほかのデバイスのエージェントから使う（`--mcp-http`）

tailnet のほかの場所にいるエージェントから使うには、次のように起動します。たとえば xAI のエージェントの Grok Bot では、そのクラウドのコンピュータが Tailscale の OAuth apps で tailnet に入ります。

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' --mcp-http
```

`run` は、次のものを除いた同じツールを、ノードから HTTP で提供します。

- プリセットのツール：`list_presets`、`activate_preset`、`deactivate_preset`
- ルールのツール：`list_rules`、`explain_rules`
- マーカーのツール：`add_marker`、`list_markers`

URL（`http://reqcove.<tailnet>.ts.net:8090/mcp`）と、エージェントに渡すヘッダー（`Authorization: Bearer <トークン>`）も表示します。`reqcove links` でもう一度表示できます。ターミナルでないときは、`reqcove links` だけが表示します。

- Grok Bot：
  1. 「Connect apps › Tailscale」で tailnet に入れます。Tailnet Lock を使っていれば、そのデバイスに署名します。
  2. 「Connect apps › カスタムコネクタを追加」を開きます。種類は「リモート HTTPS」です（名前は HTTPS ですが、tailnet の `http://` の URL で使えます。tailnet の中は WireGuard で暗号化されています）。サーバー URL にその URL、HTTP ヘッダーにキー `Authorization` と値 `Bearer <トークン>` を入れます。ヘッダーの値は画面に出さずにコピーできます：`printf 'Bearer %s' "$(cat ~/.reqcove/mcp-token)" | pbcopy`
  3. チャットで頼んでください。設定画面では、このコネクタは「エラー」でツール 0 個と表示されます。Grok Bot が tailnet に届くのはチャットの中だけだからです。
- ほかのコンピュータの Claude Code（ヘッダーは `~/.claude.json` に保存されます）：
  `claude mcp add --transport http reqcove-remote http://reqcove.<tailnet>.ts.net:8090/mcp --header "Authorization: Bearer <トークン>"`
- ほかのコンピュータの Codex（トークンはその環境変数に入れます）：
  `codex mcp add reqcove-remote --url http://reqcove.<tailnet>.ts.net:8090/mcp --bearer-token-env-var REQCOVE_TOKEN`。
  Codex は MCP ツールを呼ぶたびに承認を求めます。承認を求められない `codex exec` では、このサーバーに `default_tools_approval_mode = "approve"` を設定します。

注意点は次のとおりです。

- 呼べるのは、tailnet にある自分のデバイス（タグなし）で、トークンを持つものだけです（[セキュリティの詳細](#security-mcp-http)）。タグ付きのデバイスは拒否します（`run` が一度ログに出します）。エージェントのデバイスを制限する目的で、タグを付けないでください。
- エージェントが読んだものは、そのエージェントのコンピュータと、モデルの提供元に渡ります（Grok Bot なら xAI のクラウド）。エージェントを止めるには、状態ディレクトリの `mcp-token` を削除して `run` を再起動するか（削除しない限り、トークンは起動のたびに同じです）、そのデバイスを tailnet から外します。
- `run` を再起動しても、再接続は要りません（止まっている間の呼び出しは失敗します）。記録は空から始まり、再起動前のカーソルは拒否します。
- 呼び出しは `run` のログで確かめられます（`--mcp-http: grokbot-user-1 (100.104.0.1) called "list_flows"`）。「確認します」と言うだけで呼んでいないエージェントは、ログに行が出ません。
- 1 台のデバイスから呼べるのは、1 秒におよそ 10 回までです。超えると、しばらく `429` が返ります（`run` は 1 分に 1 回ログに出します）。
- 通信は HTTP のままですが、tailnet の暗号化（WireGuard）の中を通ります。コンテナでも同じフラグで動き、ポートの公開は不要で、トークンは `docker exec -it 名前 reqcove links` で表示できます（[コンテナ](container.ja.md#3-エージェント)）。

確認状況：Grok Bot で確認しました（status、フロー、ボディの取得。`run` の再起動後も同じチャットで継続。コンテナの `run`）。この Mac の Claude Code（`claude -p`）と Codex（`codex exec`）からも、tailnet 越しに確認しました（どちらも status を取得）。ほかのコンピュータ（tailnet にいる macOS の VM）からも、ノードの名前と IP の両方で呼べることを確認しました。

<a id="security-mcp-http"></a>

<details>
<summary>セキュリティの詳細：トークン、ツールが返さないもの、呼び出しの回数の上限</summary>

呼べるデバイスと、答えの行き先は、[SECURITY](SECURITY.ja.md#http-経由の-mcp--mcp-http) にあります。そのほかの点は次のとおりです。

- あなたのデバイスどうしを見分けるのは、トークンです。エージェントのデバイスも、あなたのほかのコンピュータも、あなた自身のデバイスの 1 つになるからです。トークンは定数時間で比較します。別のオリジンのブラウザのページからのリクエストは拒否します。
- トークンはログの行、`reqcove status`、ツールには出しません。エージェントがそれらを実行することがあるからです。`-t` を付けて動かしたコンテナでは、`docker logs` にトークンが残ります。
- `--mcp-http` には専用のサーバーがあります。このサーバーにはプリセットのツール、`list_rules`、`explain_rules`、マーカーのツール（`add_marker`、`list_markers`）がありません。
- `capture_stats` と `status` は `resolve` のルールと上流プロキシのアドレスを返しません。ただし、`rules_error` は返します。`--rules-reload` での変更が `resolve` の行で失敗すると、エラーに、その行のホストとアドレスが出ることがあります。エラーを引用する `status` の `next_steps` も同じです（コードから判断したものです）。
- `run` は HTTP でのツール呼び出しをログに出します。出すのは、呼んだデバイスとツールの名前で、引数は出しません。トークンがないリクエストと、トークンが誤っているリクエストもログに出します。
- 各デバイスが呼べるのは、1 秒におよそ 10 回です（同時には 30）。それを超えた呼び出しには `429 Too Many Requests` を返します。そのため、1 台のデバイスでエージェントが暴走しても、`run` はほかのデバイスの呼び出しに応答し続けます。呼び出しは、呼び出し元が切断すると終わります。

確認状況：テスト（本物の tailnet で、別のユーザーのデバイスが拒否されること。トークン、`Host`、オリジンの確認。サーバーにないツール。`capture_stats` と `status` が返さないもの。429。呼び出し元の切断で呼び出しが終わること）。この Mac から tailnet 越しに試し、Grok Bot でも試しました。

</details>

## 自分でフローを見る

### iPhone で見る（`--ui`）

通信を送っているアプリの横で、フローを見たいときに使います。

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' --ui
```

`run` は、ノードの 80 番ポートで読み取り専用のページを提供し、そのリンクを QR コードと一緒に表示します。リンクは `reqcove links` でもう一度表示でき、ターミナルでないときは `reqcove links` だけが表示します。iPhone のカメラで読み取ると、Safari で一覧が開きます。一覧は 1 秒ごとに新しいフローを追います。Split View でアプリと並べることもできます。フローをタップすると、ヘッダーとボディを確認できます。MCP ツールが返すものと同じく、マスク済みです。

- 検索欄に入力すると、その場で URL とヘッダーを絞り込みます。「bodies too」をオンにすると、保持しているボディの先頭も対象になり、一覧は新しいフローを追わなくなります（すべての記録を調べるためです）。ステータス（2xx〜5xx、応答なし）や、フローのページからホストでも絞り込めます。
- Clear はそれまでのフローを一覧から隠します。「Show all」で戻ります。削除はしないので、エージェントからは引き続き見えます。
- Live / Paused で、新しいフローを追うかどうかを切り替えます。下にスクロールしている間は一覧を動かさず、新しいフローの件数を表示します。件数をタップすると、新しいフローが表示されます。
- tailnet にある自分のデバイスからは、すべてのデバイスのフローが見えます。`--device` に指定した他人のデバイスからは、そのデバイス自身のフローだけが見えます（[それ以外のデバイスと、トークンの扱い](#security-ui)）。
- リンクは起動のたびに同じなので、再起動後もブックマークから開けるはずです。リンクを変えるには、状態ディレクトリの `ui-token` を削除して起動し直します。
- Tailscale はオンにしておく必要があります。Exit Node や [Remote Proxy](#exit-node-を使わずに-wi-fi-のプロキシでつなぐ) は使っていなくてもかまいません。このページ自身の通信は記録されません。

確認状況：iPhone で確認しました（カメラから開く、新しいフローを追う、検索、Clear と Show all、`run` の再起動後に Safari で開き直す）。Linux（Ubuntu 24.04、arm64）で動かした `run` でも、新しいフローを追うことを確認しました（2026-11-15）。

<a id="security-ui"></a>

<details>
<summary>セキュリティの詳細：ページを読める人と、その確認が及ばないもの</summary>

要点は [SECURITY](SECURITY.ja.md#ページ--ui) にあります。ページの中身は MCP ツールが返すものと同じで、同じようにマスクされています。読めるのは次のとおりです。

- あなた自身のデバイスと、`--device` のデバイスだけです。ほかのデバイスには何も返しません。
- 別のユーザーの `--device` のデバイスに見えるのは、自分のフローだけです。一覧でも ID の指定でも同じです。件数と次の手順も、自分の分だけが見えます。ほかのデバイスのフローも名前も見えません。あなた自身のデバイスからは、すべてのデバイスのフローがデバイスの名前と一緒に見えます。
- トークンを持つブラウザだけです。`run` が表示するリンクを開くと、トークンが HttpOnly、SameSite=Strict の Cookie として設定されます。Cookie の有効期間は 400 日です。同じ iPhone のほかのアプリはポートには届きますが、トークンがなければページを読めません。リンクが漏れても、使えるのは上のデバイスからだけです。
- トークンは起動のたびに同じです。そのため、リンク、ブックマーク、Cookie は、`ui-token` を削除して起動し直すまで使えます。削除したあとは 403 になります。
- `Host` でノードの名前を指定したリクエストだけです。iPhone が開いたサイトが DNS リバインディングで自分の名前をノードに向け、ページを自分のものとして読むことはできません。
- GET と HEAD だけです。リクエストが Remote Proxy を通ってきたときも同じです。検索フォームの送り先はページ自身で（CSP の `form-action 'self'`）、Clear は一覧からフローを隠すだけです（URL に `since` を付けます）。何も削除しません。
- スクリプトはページ自身の `/app.js` だけです。Content-Security-Policy は、ほかのスクリプトもインラインのスクリプトも許しません。`/app.js` は 1 秒ごとに `/flows.json` で一覧を取得し、DOM の呼び出しと `textContent` だけで一覧に入れます。そのため、サイトがヘッダーやボディに書いたものは、テキストのまま表示されます。`/app.js` はキャッシュされません（`no-store`）。

これらの確認が及ばないものもあります。

- ページは Safari を通ります。Safari の履歴には、表示したフローのページの URL、トークン付きの最初のリンク、検索の URL と検索した語が残ることがあります。最初のリンクは、デバイスがなければ使えず、`ui-token` を削除するまで有効です。`--no-redact` のときにシークレットの値で検索すると、その値が履歴に残ります。
- 32 段より深くネストした JSON のボディは、字下げせず、そのまま表示します。深いネストを字下げすると、深さの 2 乗に比例してメモリを使うからです。

トークンはログイン用の URL と同じく、`run` のターミナルと `reqcove links` にだけ出ます。ログの行にも MCP ツールにも出ません。

確認状況：テスト（読めるデバイスやブラウザについての各項目。node の代役の DOM で `/app.js` を動かすテスト）。

</details>

### HAR ファイルに書き出す（`reqcove har`）

`reqcove run` が動いている間に実行します。

```sh
reqcove har > flows.har
```

フローを HAR 1.2 のファイルに、古い順で書き出します。デフォルトでは新しいほうから 1000 件を書き出し、`--limit 0` ですべてを書き出します。`--host`、`--device`、`--since 10m`、`--until`、`--status 4xx`、`--method`、`--user-agent` で絞り込めます。

- 中身は MCP ツールが返すものと同じです。届いた時点でマスク済みで、ボディは先頭だけです（切り詰めたボディは、コメントにその旨が入ります）。マスクで確認できなかったボディは含まれません。`run --no-redact` のときは何もマスクされず、ファイルのコメントにその旨が入ります。
- ファイルのパーミッションはシェルの設定に従うので、ほかのユーザーから読めることがあります（[SECURITY](SECURITY.ja.md#記録するもの)）。ほかの人も使うコンピュータでは、`(umask 077; reqcove har > flows.har)` とすれば自分だけが読めるファイルになります。そうしないなら `/tmp` には置かず、リポジトリの中にも置かないでください。

確認状況：Chrome の開発者ツール（Network）に読み込めることを確認しました（リクエスト、マスクされたヘッダー、レスポンスが見えます）。試していないもの：Charles、Proxyman で開くこと。HAR 1.2 の必須項目を出力することは、仕様から判断したものです（検証ツールは実行していません）。

### mitmweb で見る（`--web`）

リクエストの編集やリプレイができる、mitmproxy 自身の画面を使いたいときに使います。

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' --web
```

mitmdump の代わりに mitmweb が起動します。開くには、`run` か `reqcove links` が表示するリンクか QR コードを使います。このコンピュータからは `http://127.0.0.1:8081`（ほかの run が 8081 を使っていれば 8091〜8099。[アドレスは 2 つ](several-exit-nodes.ja.md#ポート)）、tailnet にある自分のデバイスからはノードの 8081 番ポートで開けます。

- 何もマスクされません。パスワードを持つ人は誰でも、リクエストを編集してリプレイでき、mitmweb のオプション（スクリプトを含みます）を変えられます。オプションを変えると、このコンピュータでコードが動きます（[セキュリティの詳細](#security-web)）。
- ボディは 1 つ 2 MB まで表示し、新しい 1 万件のフローと、合計 256 MB までのボディを保持します（[この上限の数え方](#security-web)）。
- リンクは起動し直しても変わりません。トークンは状態ディレクトリの `web-token` にあります。再起動後はリンクをもう一度開いてください。トークンなしのブックマークでは、トークンの入力を求められます。
- Capture タブの「Run SOCKS Proxy」は、オンのままにしてください。オフにすると、デバイスの HTTP(S) が止まります。そこにあるほかのモードは Reqcove では使いません。変更した設定は reqcove を再起動すると元に戻ります。

確認状況：Exit Node を使っている iPhone から、macOS と Linux（Ubuntu 24.04、arm64）で動かした `run` で確認しました（2026-11-15）。mitmweb で設定を変えても Reqcove の記録の範囲とマスクが変わらないことは、コードから判断したものです（試していません）。

<a id="security-web"></a>

<details>
<summary>セキュリティの詳細：mitmweb に届く人、パスワード、オプションで変わること</summary>

表示するものと、届く人は、[SECURITY](SECURITY.ja.md#mitmweb--web) にあります。そのほかの点は次のとおりです。

- mitmweb は 127.0.0.1 で待ち受けます。パスワードは `web-token` を削除して起動し直すまで変わりません。パスワードは 0600 のファイルで渡し、コマンドラインでは渡しません。
- ノードはあなた自身のデバイスのために、自分の 8081 番ポートを mitmweb に中継します。別のユーザーの `--device` のデバイスにも、ほかの誰にも中継しません。中継してもパスワードは必要で、できることはこのコンピュータで mitmweb を開いたときと同じです。
- Remote Proxy を使うスマートフォンも、同じように mitmweb に届きます。ノードの 8081 番ポートへのリクエストと WebSocket のトンネルを mitmweb に送ります（あなた自身のデバイスだけです）。すでに開いている WebSocket は、デバイスがあなたのものと見なされなくなっても、開いたままです。
- ターミナルでは、`run` がトークン付きのリンクを表示します。リンクはスクロールバックに残り、トークンのファイルを削除するまで有効です。ターミナルでないところでは表示しません。`reqcove links` は、`links` のファイルから読んでもう一度表示します。
- ブラウザがノードを通してパスワード付きのリンク（`?token=`）を開くと、mitmweb がそれを受け付けたあとで、パスワードを除いた同じ URL へのリダイレクトで応答します。そのため、パスワードはアドレスバーに残りません。Safari の履歴が最初の URL を保持するかどうかは確かめていません。
- mitmweb の Cookie は mitmweb の再起動をまたいで使えません。mitmweb は起動のたびに作る鍵で Cookie に署名するからです（mitmweb のコードから判断したものです）。再起動のあとは、もう一度リンクが必要です。
- mitmweb は、mitmproxy が復号したすべてのフローを表示します。HTTP/2 の接続の再利用で許可した接続に相乗りした、`--allow-hosts` にないホストへのリクエストも含みます。リクエストごとの確認はそれらを Reqcove の記録から外すだけです。
- ボディはそれぞれ 2 MB まで、全体をマスクなしで表示します（mitmproxy はストリームするボディを保持しないので、Reqcove が渡します）。保持するのは新しい順に 10,000 件のフローと 256 MB のボディです。この上限が数えるのは終わったフローです。進行中のフロー（届き続けるダウンロードやイベントストリーム、応答を待っているリクエスト）は終わってから数えます。その間に保持しているボディ（片方向につき 2 MB まで）は、上限の外です（コードから判断したもので、測っていません）。

mitmweb のオプションで変わることは、次のとおりです（コードから判断したもので、試していません）。

- 変わるのは mitmproxy の動作だけで、Reqcove が mitmproxy を起動し直すまで続きます。Reqcove の記録は `--allow-hosts` の範囲に絞られ、マスクされたままです。Reqcove が、届いた時点でどちらももう一度確かめるからです。
- Capture タブで SOCKS プロキシを切ると、デバイスの HTTP(S) が止まります。Reqcove は SOCKS プロキシを通してデバイスの通信を mitmproxy に渡しているからです。
- そこで別のモードを有効にすると、そのモードは 127.0.0.1（Reqcove が設定する待ち受けホスト）で待ち受けます。このモードには Reqcove のデバイス名の確認も、このコンピュータと LAN の拒否も働きません。

確認状況：mitmweb の代役を使ったテスト（リダイレクト）。Exit Node を使う iPhone から試しました。

</details>

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
| gRPC のアプリ | 呼び出しとステータス。protobuf のメッセージは構造だけ、`--proto` を渡せば名前付きで（[詳しく](#grpc)） | iPhone の試験用アプリ（URLSession で Connect、gRPC-Web、gRPC）と E2E テスト |

### 証明書ピンニングをするアプリを通す（`--pass-hosts`）

証明書ピンニングをするアプリは Reqcove の証明書を拒否するので、そのホストへのリクエストは失敗します。`reqcove status` が、該当するホストと、`run` に付ける `--pass-hosts` を表示します。それを付けて起動すると、そのホストは復号せずに通り、アプリが動きます。

```sh
reqcove run --device iphone --allow-hosts '*' --pass-hosts '*.example-cdn.com,api.example.com'
reqcove run --device iphone --allow-hosts '*' --pass-hosts @pass-hosts.txt   # 1 行に 1 ホスト
```

- そのホストは接続だけを記録します。記録するのはホスト、接続先サーバー、時刻、バイト数で、`list_passthrough` で見られます。URL や中身は記録しません。
- その接続は `--rules` と `--upstream-proxy` の対象外です。ただし mitmproxy がそれでも復号するリクエスト（平文の HTTP や、許可したホストの接続に相乗りしたもの）は、記録されず `--rules` も適用されませんが、`--upstream-proxy` は通ります。
- TLS ハンドシェイクのあとで行うピンニングは、どこにも表示されません。
- 自分のアプリなら、ピンニングを外したビルドを使ってください。Android のアプリが CA を拒否するのは、別の理由です（[Android](#android-を記録する)）。

確認状況：iPhone で確認しました。`--pass-hosts` のホストの復号されたリクエストが `--upstream-proxy` を通ることは、テストで確かめました。`--rules` が適用されないことは、コードから判断したものです。

### HTTP として読まれない接続（raw TCP）

mitmproxy は許可したホストへの接続をどう読むかを、TLS なら復号してから決めます。HTTP と判断しなかった接続は、raw TCP として中継します。アプリは動きますが、その接続が運ぶものはフローとして記録されません。raw TCP になるのは次の場合です。

- mitmproxy が知らない ALPN の名前で、サーバーが先にデータを送るか、クライアントのバイトが HTTP に見えない接続（それ以外は HTTP/1 として読むので、ほかのプロトコルを使うクライアントは失敗します）
- HTTP に見えないバイトの接続
- リクエストが WebSocket 以外の `101` でアップグレードした先（そのリクエスト自体はフローになります）

Reqcove はその代わりに接続を記録します。

- `list_passthrough` が `reason: raw_tcp` として返します。返すのは、ホスト、接続先サーバー、時刻、クライアントが出したプロトコルと決まったプロトコル、向きごとのバイト数（TLS なら TLS の内側の数）です。バイトそのものは返しません。こうした接続は `--pass-hosts` のものとは別に 1000 件まで保ちます。
- `capture_stats` が数えます（`raw_tcp`。デバイスとホストごとの数は `raw_tcp_hosts` で、多い順に 30 件）。`list_devices` もデバイスごとに数えます（`raw_tcp`）。
- `reqcove status` が、次の手順の中でそのホストを示します。
- ホストで絞った `list_flows`、`search_flows`、`summarize`、`wait_for_flows` は、そうしたホストなら `note` でそう伝えます。

何も記録されず、数えられもしない接続もあります。mitmproxy が自分で素通しする接続（Apple のホスト、`--allow-hosts` にないホスト、mitmproxy がアドレスでしか知らない接続）、一覧にない別の名前のためにアプリが開いた接続に相乗りした、許可したホストの HTTP/2 のリクエスト、Encrypted Client Hello を使う TLS です。それぞれの場合と、何を許可すればよいかは、masking.ja.md の[記録が残らない接続](masking.ja.md#記録が残らない接続)にあります（要点は [SECURITY](SECURITY.ja.md#拾えないもの)）。

確認状況：E2E テスト（先にデータを送るサーバーとの知らない ALPN の接続と、`101` でアップグレードした平文の HTTP）と、単体テスト（`note` と 1000 件の上限）で確かめました。mitmproxy を使った手作業（2026-11-15）では、知らない ALPN で HTTP/1 のバイトを送る接続、待っているサーバーにほかのバイトを送る接続、TLS の上の `101` を試しました。iPhone では試していません。

### gRPC

gRPC の呼び出しは 1 件のフローになります。パスがメソッド名（`/pkg.Service/Method`）です。

- ステータス：一覧の行と `summarize` に `grpc_status` が出ます（`0` が成功、`16` が UNAUTHENTICATED など。トレーラーが届くまでは `pending`）。メッセージのない答え（trailers-only。エラーのときの普通の形）ではレスポンスのヘッダーから、それ以外はトレーラーから読みます。トレーラーは HTTP/2 のもので、gRPC-Web では最後のフレームです（残したボディの先頭に入っているときだけで、64 KiB を超えるボディでは読めません）。
- `grpc_message` はデコードしてマスクします（`--no-redact` のときは送られたまま）。
- トレーラーは検索の対象になり、`diff_flows` で比べられ、HAR ではコメントに入ります。
- メッセージ：ボディの注記には、メッセージの数と大きさが出ます。JSON のメッセージ（`application/grpc+json`、`connect+json`）は 1 行に 1 つずつ、JSON としてマスクして返します。protobuf のメッセージは下のとおりです。
- Connect のストリーム：最後のフレーム（エラーとトレーラー。JSON）は、`[end of stream]` として JSON と同じくマスクして返します。ストリームの結果はこのフレームにあり、`grpc_status` には出ません。
- `-bin` で終わるメタデータ（バイナリ）は、大きさだけを出します。

protobuf のボディ（gRPC のメッセージや、`application/x-protobuf` など）はテキストではないので、Reqcove は中身のバイト列ではなく、Reqcove が書き起こしたものを返します。ボディの `view` を見ると、書き起こしたものだと分かります。スキーマがないときは構造だけです。

- フィールドの番号、型、長さ
- 文字列は `string(12)` のように長さだけ（中身は出しません）
- レスポンスの数値。リクエストの数値は 128 未満のもの（enum や真偽値など）だけを出すので、128 未満なら PIN などもそのまま出ます。それより大きいもの（数値で送ったコードなど）は、バイト数だけを出します。

たとえば次のようになります。

```
1: 150
2: string(12)
3 {
  1: string(3)
}
```

`--proto FILE` に、コンパイルしたスキーマ（`protoc --descriptor_set_out=FILE --include_imports`）を渡します。型がわかるメッセージは、フィールドの名前付きの JSON として出し、JSON と同じく名前でマスクします。

- 型は、パスが示すメソッド（gRPC、gRPC-Web、Connect、Twirp の `/pkg.Service/Method`。リクエストでは入力、レスポンスでは出力の型）か、Content-Type の `messageType` から決めます。
- `bytes` のフィールドは長さだけ、スキーマにないフィールドは構造だけを出します。

`--no-redact` のときは、protobuf のボディは届いたまま残します。

Google の SDK など、gRPC-core の上に作ったアプリは、iPhone が信頼する CA ではなく、自前の CA の一覧を使うので、呼び出しは TLS の失敗として出ます（gRPC のメーリングリストによるもので、試していません）。gRPC のライブラリに信頼する証明書を指定するアプリも同じです。デバッグ版で Reqcove の CA を信頼させれば別です（試していません）。

grpc-swift 2 はどちらのトランスポートでも、ALPN で `h2` より先に `grpc-exp` を出します（grpc-swift 1 も同じであることは、ソースから判断したものです）。これを選ぶサーバーもあります（Connect のデモサーバーがそうです）。Reqcove はサーバーに `grpc-exp` を外して `h2` を出すので、こうした呼び出しも HTTP/2 で通り、記録されます。`h2` を受け付けず `grpc-exp` だけを受け付けるサーバーでは、こうした呼び出しは Reqcove を通すと失敗します。クライアントが `h2` も出すときは、サーバーに `grpc-exp` を出さないためです（コードから判断したもの。そうしたサーバーは見つかっていません）。

確認状況：iPhone（iOS 27.3）で、試験用アプリが URLSession から Connect のデモサーバーを Connect、gRPC-Web、gRPC で呼び、`--proto` も付けて試しました。grpc-swift 2 はどちらのトランスポートも試しています。テストだけで確かめたもの：スキーマなしの表示、Connect のストリームの最後のフレーム、トレーラーにステータスが入る 64 KiB を超えるボディ、trailers-only のエラー、gRPC のレスポンスの名前付きの表示（iPhone で試したビルドでは出ませんでした。そのあと直しましたが、iPhone では試し直していません）。

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

確認状況：Android 14 のデバイス（Chrome は復号、ほかのアプリはすべて拒否）と、サンプルアプリ（`domain-config` でこのように指定したホストは復号、指定していないホストは CA を拒否）と、上の `debug-overrides` を書いたデバッグ用のビルド（両方のホストから応答あり）で確認しました。

### iOS シミュレーターを記録する（`--local-proxy`）

シミュレーターのアプリはこのコンピュータのネットワークを使うので、Exit Node では中継できません。`--local-proxy` を付けると、代わりに `127.0.0.1:8082` に HTTP プロキシを開き、そこを通ったリクエストを `local` というデバイスとして記録します。

```sh
reqcove run --allow-hosts api.example.com --local-proxy   # iPhone も記録するなら --device も
```

- パスワードはありません。このコンピュータのプロセスはどのユーザーのものでも、このプロキシを使えます。必要な間だけ有効にしてください（[セキュリティの詳細](#security-local-proxy)）。
- macOS：Charles や Proxyman と同じように、`run` がシステムの Web プロキシ（HTTP と HTTPS、有効なネットワークサービスすべて）をこのプロキシに向け、止まるとき（Ctrl-C、`kill`、ターミナルを閉じたとき）に元の設定へ戻します。起動中のシミュレーターには Reqcove の CA も追加します（`xcrun simctl keychain … add-root-cert`）。あとから起動したシミュレーターには、表示されるコマンドで追加してください。
- Linux：設定は何も変更しません。アプリをプロキシに向け（`HTTPS_PROXY=http://127.0.0.1:8082`）、CA を信頼させてください。
- シミュレーターだけでなく、このコンピュータのすべてのアプリの通信がこのプロキシを通ります。復号して記録するのは `--allow-hosts` のホストだけですが、そのホストは、Reqcove の CA を信頼していないアプリ（Mac の Safari など）ではつながらなくなります。
- `kill -9` や異常終了のあとは、次の `run` か `reqcove cleanup` がプロキシの設定を戻すまで（またはシステム設定で自分で戻すまで）、システムのプロキシを使うアプリがつながりません。
- このコンピュータ、LAN、tailnet（IPv4 と IPv6、`*.ts.net` も）、`*.local` はプロキシの例外に入れるので、これまでどおり直接つながります。名前解決はこのコンピュータと同じ方法で行い（VPN、split DNS、検索ドメインも有効）、`--dns` は使いません。このコンピュータ自身やリンクローカルアドレスに解決される名前は、`/etc/hosts` にあるものを除いて拒否します（[セキュリティの詳細](#security-local-proxy)）。
- 自動プロキシ構成（PAC）と認証付きプロキシの設定は、変更しません。

このコンピュータのブラウザの通信も、警告で止めるのではなく記録したいときは、このコンピュータに Reqcove の CA を一度信頼させます。ブラウザの通信は `local` として、シミュレーターの通信と一緒に記録されます。コマンドは `run` が表示し、やめ方は `reqcove status` と `reqcove cleanup` が表示します。信頼させると、CA の秘密鍵を持つ人は、このコンピュータに対しても任意の HTTPS サイトになりすませます（[セキュリティの詳細](#security-local-proxy)）。

- macOS（TLS だけを信頼。パスワードを求められます）：`security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem`。Firefox は独自の証明書ストアを使うことがあります。やめるには、`reqcove status` が表示するコマンドを実行するか、キーチェーンアクセスで CA を削除します（信頼の設定も一緒に消えます）。
- Debian と Ubuntu：`sudo cp ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/reqcove.crt && sudo update-ca-certificates`。Fedora：`/etc/pki/ca-trust/source/anchors/` に置いて `sudo update-ca-trust`。
- Linux の Chrome と Chromium：`certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n Reqcove -i ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem`。Node：`NODE_EXTRA_CA_CERTS=` にそのファイルを指定します。Python：更新後のシステムの CA バンドルを指定します（そのファイルだけを指定すると、ほかの CA がすべて使えなくなります）。

確認状況：macOS 27 で確認しました。確認したのは、システムの Web プロキシが設定され、Ctrl-C で元に戻ること、起動中のシミュレーターに CA が入り、iOS 27 のシミュレーターの Safari の通信が `local` として記録されること、このコンピュータに CA を信頼させることとやめること（信頼させている間、Mac の Chrome で許可したホストが警告なしに記録されました）、RoamRun 0.12.0（とその PR #253）と一緒に使えることです。試していないもの：プロキシの例外のアドレスの書き方をアプリが守るか、PAC や認証付きプロキシのある環境、Linux。

<a id="security-local-proxy"></a>

<details>
<summary>セキュリティの詳細：ローカルプロキシが通すもの、システムのプロキシ設定、このコンピュータでの CA の信頼</summary>

使える人と、このコンピュータのブラウザで開いたページがプロキシを通して届く先は、[SECURITY](SECURITY.ja.md#ローカルプロキシ--local-proxy) にあります。そのほかの点は次のとおりです。

- アプリは、このプロキシがないときと同じように、このコンピュータ自身の名前解決で、LAN、VPN、tailnet に届きます。このコンピュータ、LAN、tailnet は、システムのプロキシの例外に入っているので、アプリはそこへ直接届きます。
- IPv6 は拒否します。このコンピュータ自身（ループバック、自身のアドレス）やリンクローカルアドレスに行き着く名前も拒否します。ただし、このコンピュータの `/etc/hosts` にその名前があるときは通します。拒否しなければ、このコンピュータのブラウザで開いたページが DNS リバインディングで自分の名前をそこに向け、プロキシを通してこのコンピュータのサービスに届いてしまいます。
- ページが自分の名前を LAN、VPN、tailnet のアドレスに向けることは、なおできます。プロキシはそれを通します（VPN の中の名前を使い続けられるようにするためです）。プロキシを使わないブラウザでも同じことは起きます。ただし、プロキシを通すとブラウザにはアドレスが見えないので、ブラウザ自身のプライベートネットワーク向けの保護（Chrome の Private Network Access）が働きません。`--local-proxy` は、必要な間だけ有効にしてください。
- Apple のホストは復号しません。
- macOS では、`run` が動いている間、システムの Web プロキシをこのプロキシに向けます。元の設定は状態ディレクトリ（0600）に保存し、`run` の停止時（SIGHUP でも）、次の起動時、`reqcove cleanup` のどれかで元に戻します。まだ戻していない設定を上書きして保存することはありません。cleanup も、設定を保存している間は状態ディレクトリを削除しません。Reqcove が強制終了されると、システムのプロキシを使うアプリは、設定を戻すまで接続できません。
- Reqcove がこのコンピュータに CA を信頼させることはありません。そのためのコマンドは `run` が表示します（TLS だけ、このユーザーだけが対象です）。信頼させると、`<state>/mitmproxy/` にある CA の秘密鍵で、デバイスだけでなくこのコンピュータに対しても、どの HTTPS サイトにもなりすませるようになります。状態ディレクトリと、そのコピーやバックアップを人に渡さず、終わったら信頼を外してください（外し方は `reqcove status` と `cleanup` が、フィンガープリントを添えて表示します）。

確認状況：テスト（このコンピュータやリンクローカルアドレスに行き着く名前を拒否すること）。本物の `networksetup`（設定と、Ctrl-C での復元）と iOS 27 のシミュレーターで試しました。

</details>

### Web アプリのバックエンドを記録する

Web アプリがほかの API を呼ぶ通信（Rails のサーバーが決済 API を呼ぶ、など）は、iPhone ではなくサーバーから出ます。Reqcove に見えるのは、サーバーがその通信を Reqcove に通し、Reqcove の CA を信頼しているときだけです。tailnet にある自分のマシンで動くサーバーなら、そのマシンを `--device` に指定し、サーバーにノードの [Remote Proxy](#exit-node-を使わずに-wi-fi-のプロキシでつなぐ) を指定します。

```sh
reqcove run --device dev-server --allow-hosts api.example.com
# dev-server で：変数は両方指定（Ruby の Net::HTTP は HTTPS でも http_proxy を見る）
# CA バンドルには Reqcove の CA を追加（システムの CA バンドルと mitmproxy-ca-cert.pem を連結）
http_proxy=http://100.x.y.z:8080 https_proxy=http://100.x.y.z:8080 SSL_CERT_FILE=bundle.pem bin/rails server
```

- 呼び出しはそのマシンの名前で記録されます。変更するのは、サーバーの環境変数だけです。
- データベースや Redis への接続は、80 番・443 番の HTTP(S) ではないので見えません。
- ブラウザからアプリへのリクエストは、別の経路です。iPhone からなら、許可したホストへのリクエストを `map_remote` で開発サーバーに送れます（[ルール](#ルールを書く--rules)）。

確認状況：この Mac をデバイスにして、Rails 8 のアプリから Net::HTTP と Faraday で API を呼んで確認しました（CA がないと Ruby が証明書を拒否して TLS の失敗が記録され、CA があると両方の呼び出しが記録されました）。試していないもの：ほかのクライアント、別のマシンのサーバー。

### Exit Node を使わずに Wi-Fi のプロキシでつなぐ

ノードは **Remote Proxy** も提供しています。ノードの tailnet アドレスの 8080 番ポート（`--proxy-port`）で動く HTTP プロキシで、`--device` のデバイスが使えます。iPhone では Exit Node を選ぶ代わりに、Wi-Fi のプロキシ設定（手動）にこれを指定できます。モバイル通信にはプロキシ設定がないので、Wi-Fi でのみ使えます。

| | Exit Node | Wi-Fi のプロキシ |
|---|---|---|
| このコンピュータを通る通信 | iPhone のすべての通信（DNS、HTTP(S)、ほかのポート） | プロキシ設定に従うアプリの HTTP(S) |
| それ以外 | なし | iPhone の Wi-Fi から直接インターネットへ（記録なし） |
| モバイル通信 | 利用可 | 利用不可 |
| Tailscale アプリ | Exit Node を選択 | 接続したままにするだけ |

プロキシを通った通信は Exit Node のときと同じく、このコンピュータからインターネットに出ます。名前解決もこのコンピュータで行います。

確認状況：iPhone で確認しました（Safari の通信が記録され、`--allow-hosts` にないサイトもこれまでどおり開けました）。

### 別の Mac を記録する

`--device` に指定した Mac で、Tailscale のアプリから Exit Node を選ぶと、iPhone と同じように記録されます（[手順](another-mac.ja.md)）。Homebrew のオープンソース版の `tailscaled` では、Exit Node は選ばれた表示になりますが、その Mac の通信は通りません。

確認状況：macOS 27 の VM で確認しました。試していないもの：その Mac の iOS シミュレーター（シミュレーターが Reqcove の CA を信頼していれば、Mac の通信と一緒に通るはずです）。

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
- リクエストを別のサーバーへ送るには、`Host` を変える `modify_headers` のルールではなく、`map_remote`（か `resolve`）を使います。そうした `modify_headers` のルールはそれだけでは適用されません（次の項目）。パスだけを変えてホストはそのままの `map_remote` も、リクエストを別の先へ送るルールとして働きます。mitmproxy は、アプリが接続したアドレスではなく、そのホストに名前で接続します（名前解決はこのコンピュータで行います）。このときヘッダーのルールは適用されます。
- `modify_headers` が適用されるのは、その `Host` へ行くリクエストと、そのレスポンスだけです。Host のアドレスへ送られたリクエスト、HTTPS でその TLS の名前へ送られたリクエスト、または `map_remote` か `resolve` が送り先を決めたリクエストです。`Host` を変えるルールは `map_remote` か `resolve` と一緒のときだけ適用されます。それだけでは、そのリクエストのヘッダーのルールはどれも適用されません。適用されなかったときは、記録の `rewrites` にそう出ます（[セキュリティの詳細](#security-rules)）。
- `map_local` が応答するのは、ボディが 1 MiB 以下で長さが分かっているリクエストだけです。それ以外は本来の宛先へ送ります（記録にその旨が残ります）。
- 長さのない HTTP/2 の GET（HEAD、OPTIONS、DELETE も）には、ボディなしでストリームが終わったときに `map_local` が応答します。ボディのない GET と同じくヘッダーで終わったときと、空の DATA フレームで終わったときです（Go のクライアントは、長さの分からないボディが空だったときにこれを送ります）。それでもボディを送ってきたものには 502 を返してエラーとして記録し、そのボディは保持しません。12.3.1 以外の mitmproxy（別の `--mitmproxy-spec`）では、ヘッダーで終わらなかったストリームは、空の DATA フレームでも 502 になります（コードから判断したもの）。
- 他人が作ったルールファイルは、中身を読んでから使ってください。ルールはアプリのリクエストを Cookie やトークンごと、書かれた先へ送れます。

確認状況：E2E テストで確認しました。確認したのは、上の各種類のルール（`map_remote` では、終わっていない POST と SSE が流れるままに相手に届くことも）、`--allow-hosts` の外のリクエストには触れないこと、ルールの値が記録に入らないこと、読み込みで断るもの、長さのない HTTP/2 の GET（Go のクライアント）です。次の点には限りがあります。

- パスだけを変える `map_remote` は mitmproxy の Python で、作ったリクエストに対して試しました。ネットワーク越しには試していません。
- macOS の URLSession は、mitmproxy を通さず、テスト用のサーバーで試しました。GET と HEAD のストリームをヘッダーで終え、DELETE と OPTIONS には長さ 0 を付けるので、どれも 502 になりません。
- iPhone のアプリが送る、長さのない HTTP/2 のリクエストは試していません。
- mitmproxy がストリームの終わりを知る仕組みは、コードから判断したものです。

#### 接続先だけを変える（`resolve`）

`resolve` は、リクエストをそのままにして、接続先だけを変えます。ステージングサーバーや新しいロードバランサー向けです。

```yaml
resolve:                        # Reqcove 独自：Host と SNI はそのままで、接続先だけ変える
  - "shop.example.com=203.0.113.10"
  - "auth.example.com=192.168.1.20:8443"
```

- その名前へのリクエストを、指定した IPv4 アドレスへ送ります（このコンピュータや LAN のアドレスも指定できます）。`Host`、SNI、記録される URL は変わらず、TLS もその名前で検証します。接続先のサーバーには、その名前の証明書が必要です（証明書のないローカルの HTTPS サーバーでは 502 になります）。平文の HTTP は検証されません。
- ポートを省略すると、リクエストのポート（アプリの 80 番か 443 番、または `map_remote` の URL のポート）を使います。`map_remote` のあとでは、書き換え後の URL のホストが対象の名前になり、SNI もそれになります。
- 名前解決はこれまでどおり行われ（iPhone が行い、Remote Proxy ではこのコンピュータが行います）、先に本物のサーバーへ接続します。公開の DNS で解決できない名前や、接続を拒否する本物のサーバーは、接続先を変えられません。
- 名前は `--allow-hosts` に入っている必要があり、名前ごとに別のアドレス（またはポート）が必要です。mitmproxy が接続をアドレス単位で使い回すためです。
- 拒否するもの：`0.0.0.0/8`、リンクローカル（クラウドのメタデータ）、マルチキャスト、Tailscale の 100.100.100.100（[セキュリティの詳細](#security-rules)）。`--upstream-proxy` と一緒に使う `resolve` も拒否します。

確認状況：E2E テストで確認しました。確認したのは、平文の HTTP がアプリの `Host` のままルールのアドレスへ送られ、送り先が記録に残ること、`map_remote` のあとの `resolve`、TLS で接続先にその名前（SNI）を求め、信頼できない証明書なら 502 になること、読み込みで断るもの（クラウドのメタデータ、100.100.100.100、名前の接続先、アドレスの共有、`--allow-hosts` にないホスト、`--upstream-proxy` との組み合わせ）です。別の名前の信頼された証明書を持つサーバーで 502 になることも試しました（[セキュリティの詳細](#security-rules)）。`resolve` のプリセットは iPhone では試していません（[下](#map_remotemodify_headersresolve-のプリセット)）。

#### ここで応答する（`mock`）

`mock` は、リクエストに書いたとおりの応答をここで返します。セッション切れや空の一覧を、アプリがどう扱うかを見るときに使います。リクエストはサーバーに送りません（HTTPS では、証明書を読むために mitmproxy がその前にサーバーへ接続していることがあります）。

```yaml
mock:                           # Reqcove 独自。最初に一致したものが、map_remote や map_local より先に応答する
  - match: {method: POST, url: "https://api.example.com/v1/login"}
    status: 401
    headers: {Content-Type: application/json}
    body: '{"error":"expired"}'
  - match: {url: "https://api.example.com/graphql", operation: Feed}
    body_file: feed.json        # ルールファイルの場所が基準
```

- `url` は、アプリが送った URL のクエリを除いた部分と完全に一致したときに当たります（ホストの大文字と小文字は区別しません）。パスのあとの `*` で終わる `url`（`https://api.example.com/v1/*`）は、それより前の部分で始まる URL すべてに当たります。クエリ、フラグメント、ユーザー名、デフォルトのポートは書けません（書いても当たることがないので、読み込みで拒否します）。ホストは `--allow-hosts` に入っていて、`--pass-hosts` に入っていない必要があります。
- `method` と `operation` は省略できます。`operation` は GraphQL の operation です（`operationName`、Apollo の `X-APOLLO-OPERATION-NAME` ヘッダー、または文書の最初の名前付き operation）。
- 応答：`status` は 100〜599 で、省略すると 200 です。ボディは書くかファイルで指定し、1 MiB までです。`HEAD`、204、304 にはボディを付けません。`Cache-Control` を書かなければ `no-store` を付けます。
- `modify_headers` との関係：リクエストに対する `modify_headers` のルールは一致を調べる前に適用され、応答に対するものはモックにも適用されます。
- 保持するもの：モックが応答するかもしれないリクエスト（メソッドと URL が一致するもの）は、ボディが届くまで全体を保持します。長さが 1 MiB を超えるものや、長さの分からない POST は、モックせずに本来の宛先へ送り、`rewrites` に `mock: skipped, …` と残します。`map_local` と同じく、長さのない GET（HEAD、OPTIONS、DELETE も）も保持します。HTTP/2 で、それでもボディを送ってきたものには、保持せずに 502 を返します（空の DATA フレームはボディではありません）。
- 記録にその旨が残ります。一覧の行に `mocked: true`、`rewrites` にルールの番号とステータス（`mock[0]: 401`）、HAR には注記が入ります。`capture_stats` の `rules_loaded` はファイルを最後に読み込んだ時刻です。

確認状況：E2E テストで確認しました。確認したのは、POST に対するヘッダー付きの 401、ボディの GraphQL operation による一致、`*` で終わる URL、HEAD、サーバーに届かないこと、拒否するルール（範囲外のステータス、ヘッダーの改行、ないファイル、`--allow-hosts` にないホスト）です。iPhone では Safari（httpbin.org）への 401 と、GitHub アプリの GraphQL の operation 1 つをモックできることを確認しました（同じ接続のほかの operation は GitHub に届きました）。

#### ファイルを読み込むタイミング（`--rules-reload`）

ファイルは mitmproxy の起動時に読み込みます（`run` の起動時と、reqcove が mitmproxy を再起動するとき）。

`--rules-reload` を付けると、変更が落ち着いた時点で読み直します。新しいルールはそのあとに始まるリクエストから適用します。処理中のリクエストは始まったときのルールのままです。

- 読み込めないファイルのときは前のルールのまま動き、`run` と `reqcove status` が理由を表示します。ただし、その間に mitmproxy が再起動すると、起動時と同じく `run` が止まります。
- ファイルに書き込めるもの（エージェントを含む）が、再起動なしで、デバイスのリクエストの行き先を変えられるようになります。

変更は 2 秒ほどで読み直されます（コードから判断したもの）。

#### ターミナルからモックを足す（`reqcove mock add`）

`reqcove mock add` は、モックを確かめてからファイルに書き足します。

```sh
reqcove mock add --rules rules.yaml --url https://api.example.com/v1/login \
  --method POST --status 401 --header 'Content-Type: application/json' \
  --body '{"error":"expired"}'
```

- ほかのフラグ：`--operation NAME`、`--body-file PATH`（入力した場所が基準で、フルパスで書きます）、`--delay-ms N`、`--fault close`、`--preset NAME`、`--description TEXT` です。
- 書く場所：モックは `mock:` の最後の項目として足し、ファイルのほかの部分（コメントや順序も）はそのまま残します。`mock:` がなければ、ファイルの最後に足します。新しいファイルは `0600` で作ります。既にあるファイルはモードを保ったまま、一度に置き換えます（隣に一時ファイルを書き、名前を変えます）。
- 断るもの：`mock:` がファイルの最後のブロックでないときや、フロー形式（`mock: []`）のときは断り、直し方を表示します。同じ名前のヘッダーを 2 回指定したときも断ります。確かめている間にファイルが変わったとき（エディタで保存したときなど）は何も書かないので、もう一度実行してください。
- 確認：書く前に、書いたあとのファイル全体を、アドオン自身の読み込み処理で確かめます。`reqcove run` が動いていれば（同じ `--state`）、その `--allow-hosts` と `--pass-hosts` も使って run が確かめます。動いていなければ、ロックファイルの mitmproxy の Python（`--uvx PATH`）で確かめ、このときホストは確かめません。断ったときは理由を表示し（ルールの中身は出しません）、何も書きません。
- 反映されるタイミング：書いたあと、モックがいつ反映されるかを表示します。run に `--rules-reload` があればすぐに反映され、そのとき有効なプリセットはすべて無効になります。なければ run を起動し直したときです。
- ターミナルでだけ動きます（`reqcove mark` と同じく、標準入力と標準出力の両方）。これは、頼まれていないエージェントが実行するのを防ぐ助けで、保証ではありません（シェルを使えるエージェントはターミナルを用意でき、どのみちファイルも書き換えられます）。`--print` は、書き込みも確認もせずにモックを YAML で表示します。ターミナルでなくても動きます。

確認状況：テストで確認しました。確認したのは、引用符、改行、`#`、`: `、制御文字、ほかの文字体系を含む値の YAML をアドオンの読み込み処理が元のとおりに読むこと、ファイルの中身が残ること（コメント、CRLF、末尾に改行のないファイル）、断る場合、本物の run による確認（範囲内と範囲外のホスト、`--pass-hosts` のホスト）と mitmproxy の Python による確認です。動いている run とデバイスでの手作業の確認はしていません。

#### エージェントが有効にできるプリセット

`preset: 名前` を付けたモックは、エージェントが有効にするまで何もしません。有効にできるのは 1 回につき最長 5 分で、何度でも有効にし直せます（上限なし。[セキュリティの詳細](#security-mock-presets)）。プリセットと同じ match（メソッド、URL、operation）の普通のモックは、読み込みで断ります（プリセットの代わりに応答してしまうためです）。エージェントはファイルを書き換えずに、503 や遅い応答、切れた接続をアプリがどう扱うかを確かめ、また無効に戻せます。

```yaml
mock:
  - match: {url: "https://api.example.com/v1/profile"}
    preset: profile-503             # 英数字と . _ -。64 文字まで
    description: the profile API is down   # 省略可。1 行、200 文字まで
    status: 503
  - match: {url: "https://api.example.com/v1/profile"}
    preset: profile-slow
    delay_ms: 8000                  # 30000 まで（URLSession のデフォルトのタイムアウトは 60 秒）
    body: '{"name":"slow"}'
  - match: {url: "https://api.example.com/v1/feed"}
    preset: feed-drop
    fault: close                    # 応答しない。HTTP/1 は接続を閉じ、HTTP/2 はストリームをリセットする
```

- ツールは `list_presets`、`activate_preset(name, minutes, times)`（最長 5 分。省略すると 5 分。`times` を付けると、最大 20 件のリクエストに応答したら無効になる）、`deactivate_preset(name)` です。使えるのはこのコンピュータのエージェント（`reqcove mcp` と `run` のソケット）だけで、`--mcp-http` からは使えません。
- 有効なプリセットはほかのモックより先に応答します。無効なプリセットはモックとして扱いません。同じ match（メソッド、URL、operation）で有効にできるプリセットは 1 つです。同じ match の別のプリセットを有効にすると、先のものは無効になります。有効なものをもう一度有効にすると、期限と回数が置き換わります。
- 一致したリクエストは Safari、別のデバイス、アプリの再試行など、誰が送ったものでも回数を使います。一覧の行には `preset: 名前` が付き、閉じたものの error には、モックが閉じたと書かれます。
- `delay_ms` と `fault: close` は普通のモックでも使えます。`delay_ms` が遅らせるのはモックの応答だけです（サーバーからの応答は遅らせません）。
- `--rules-reload` のときは、ファイルが変わると（読み込めないファイルでも）、すべてのプリセットが無効になります。mitmproxy や `run` が再起動したときも同じです。`run` は、エージェントが有効・無効にするたびにログに書きます（時間や回数で終わったものは書きません）。`reqcove status` と `status` ツールはいま有効なものを表示します。
- ファイルにプリセットを書いた時点で、エージェントがそれを有効にしてよいと同意したことになります。エージェントが `preset:` を書くのは、会話の中であなたが頼んだときだけです。記録に書かれていたことを理由には書きません。`--rules-reload` のときは、書いてすぐ有効にできます（[セキュリティの詳細](#security-mock-presets)）。

確認状況：E2E テストで確認しました。確認したのは、有効と無効、時間と回数の上限、match ごとに 1 つだけ有効なこと、ファイルの変更で無効になること、拒否、HTTP/2 の 1 つのストリームを遅らせている間に同じ接続の別のストリームにはすぐ応答すること、HTTP/1 と HTTP/2 での close です。iPhone（iOS 27.3。URLSession を使うテスト用アプリ。エージェントが MCP でプリセットを有効にした）では、次を確かめました。503 を 1 回返したあと、アプリのやり直しがサーバーに届いたこと。8 秒の遅延。close では CFNetwork が自分でやり直さなかったこと（アプリ自身のやり直しも閉じられた）。ログインへの 401。

<a id="security-mock-presets"></a>

<details>
<summary>セキュリティの詳細：モックのプリセットでエージェントにできることと、その上限</summary>

要点は [SECURITY](SECURITY.ja.md#モックのプリセット) にあります。`map_remote`、`modify_headers`、`resolve` のルールもプリセットにできます。こちらはリクエストを別の場所へ送れます（[下記](#security-presets)）。

- 起動時のスイッチはありません。プリセットを書くことが、エージェントが有効にしてよいという同意になります。
- **Reqcove のツールだけを許可されたエージェント**（MCP だけのクライアントや、サンドボックスに入ったクライアント）が、デバイスの受け取るものを変えられます。変える時点はエージェントが選び、呼び直せば、呼び続ける限り変えていられます。サイトが記録に書き込んだ文が、そうするようエージェントを誘導しようとすることがあります。
- エージェントが有効にできるのは、あなたが書いたものだけです。モックのプリセットでは、新しい中身、送り先、ホストは生まれず、このコンピュータから新しく出ていくものもありません。
- **最悪の場合**は、すべてのプリセットがずっと有効にされ続け、それぞれがサイトの名前で、あなたの書いたものを応答することです（許可したホストの HTML ページのモックは、どのモックもそうであるように、そのホストの Cookie を持って Safari で動きます）。
- **上限**は Reqcove で確かめ、mitmproxy のアドオンでもう一度確かめます。1 回につき最長 5 分で、`times` を付けると最大 20 件のリクエストまでです。有効にし直す回数に上限はありません。一致したリクエストは、誰が送ったものでも回数を使います。
- 使えるのはこのコンピュータでだけです。ツールは `run` のソケットと `reqcove mcp` にあります。`--mcp-http` 専用のサーバーにはありません。アドオンは状態ディレクトリにある自分のソケット（0600）で依頼を受けますが、受けるのは `run` が渡した秘密が付いているものだけです。
- 書き込みを送り直すことはありません。`reqcove mcp` は、呼び出しの途中で `run` への接続が切れても、書き込みを送り直しません。書き込みが反映されたかどうかは分からない、と伝えます。
- **エージェントに伝えていること。** Skill とサーバーの instructions は、プリセットを有効にするのは、ユーザーが会話の中で頼んだテストのためだけにするよう伝えています。記録やプリセットの説明に書いてあることを理由に有効にしてはいけない、とも伝えています。`preset:` をルールファイルに書くのも、ほかのルールと同じく、ユーザーが会話の中で頼んだときだけです。頼まれてプリセットを書いたエージェントは、`--rules-reload` があれば、すぐにそれを有効にできます。この場合は、会話の中での依頼が同意になります。モデルがこれを守るかどうかは、テストでは示せません。
- **見えること。** `run` は、エージェントがプリセットを有効・無効にするたびにログに出します。`status` ツールと `reqcove status` は有効なプリセットを一覧にします（mitmproxy が答えなかったときは、そう伝えます）。プリセットが応答したフローには `preset: NAME` と出ます。
- **無効になるとき。** エージェントは `deactivate_preset` で無効にできます。そうしなくても、終わりの時刻は 2 つの時計で確かめるので、コンピュータがその時刻を過ぎてスリープしていても、有効なまま残りません。すでに `delay_ms` の待ちに入っている応答は、プリセットを無効にしたあとでも 1 つ出ていきます。
- **`list_presets`** が返すのは、各プリセットが何に一致するかと、ステータス、遅延、fault です。ボディとヘッダーの値は返しません。

確認状況：テスト（`run` が作る 2 つのサーバー。アドオンの秘密。書き込みを送り直さないこと。2 つの時計）。

</details>

#### `map_remote`、`modify_headers`、`resolve` のプリセット

`map_remote`、`modify_headers`、`resolve` のルールもプリセットにできます。`rule:`（これまでどおりのルール）と `preset:` を持つマッピングで書きます。モックのプリセットと同じく、エージェントが有効にするまで何もせず、有効にできるのは 1 回につき最長 5 分です。エージェントはアプリの通信を少しの間ステージングや開発用のサーバーへ向けたり、機能フラグのヘッダーを付けたりして、また戻せます。

```yaml
map_remote:
  - {rule: "|~d api.example.com|^https://api\\.example\\.com/|https://staging.example.com/", preset: staging, description: to staging}
modify_headers:
  - {rule: "/~q/X-Feature-Flag/new-checkout", preset: new-checkout}   # リクエストだけ
resolve:
  - {rule: "api.example.com=192.168.1.20", preset: api-lan}
```

- ツールは `list_presets`（すべての種類。`kind` 付き）、`activate_preset(name, minutes)`、`deactivate_preset(name)` です。`times` はモック専用で、ほかの種類は時間だけで無効になります。
- 有効な間、`map_remote` のプリセットは一致したリクエストを、アプリの Cookie、トークン、ボディごと送り先へ送ります。`resolve` はその名前の接続先を指定のアドレスにします（Host、SNI、TLS の検証は名前のまま）。プリセットは 5 分で無効になりますが、その間に起きたことは残ります。アプリが書いたものは送り先のサーバーに残り、アプリはそこで得たトークンやキャッシュを持ち続けることがあります。有効な間に始まった WebSocket、ストリーム、長いアップロードは、無効になったあともその送り先のままです（コードから判断したものです。[セキュリティの詳細](#security-presets)）。
- `list_presets`、起動時の表示、`reqcove status` に出すのは、`map_remote` の送り先（スキームとホスト）、`modify_headers` のヘッダー名（値は出しません）、`resolve` の名前とアドレスです。フィルターや正規表現は出しません。
- 読み込みで断るもの：
  - 次のどれかに当たる `map_remote` のプリセット：置き換えが `http://` か `https://`、ホスト、`/` で始まらない（送り先を表示できないため）、送り先にユーザーやパスワードがある、ホストをリクエストから取る（`\1`）、リンクローカルのアドレスへ送る、このコンピュータや LAN のアドレス（`localhost`、`*.local`、プライベートアドレス）以外へ平文の `http://` で送る
  - レスポンスを変える `modify_headers` のプリセット（`~s`）
  - `map_local` のプリセット
  - プリセットと同じ一致条件の普通のルール（`map_remote` は同じフィルターと正規表現、`modify_headers` は同じフィルターとヘッダー）
- 送らずに 502 を返すもの：書き換えた URL が表示している送り先の外になるリクエスト（正規表現が URL の途中に一致したもの）。
- 同じ一致条件で有効にできるのは、種類ごとに 1 つです（`map_remote` は同じフィルターと正規表現、`modify_headers` は同じフィルターとヘッダー、`resolve` は同じ名前）。有効な `resolve` のプリセットは同じ名前の普通の `resolve` より先に使います。有効な `map_remote` のプリセットは普通のルールより先に、`modify_headers` のプリセットは普通のルールのあとに当てます（プリセットのヘッダーが残ります）。
- 名前は種類をまたいで共通です（モックと `resolve` のプリセットの両方を `staging` にはできません）。一覧の行の `presets` には、そのリクエストを変えたか応答したプリセットがすべて入ります（`preset` は、応答したモックのものとして残します）。
- `reqcove status` と `status` ツールの `active_presets` には、有効なものがすべての種類で入ります（`kind` 付き。mitmproxy から答えがなければ `active_presets_error`）。`capture_stats` の `presets` には、すべてのプリセットの名前が入ります。

確認状況：E2E テスト（平文の HTTP）で、どの種類のプリセットも有効な間だけリクエストを変えることと、ファイルの変更で無効になることを確かめ、読み込みで断るものは mitmproxy の Python で確かめました。LAN モードの iPhone（iOS 27.3、2026-11-14）では、このコンピュータの開発サーバーへの `map_remote` のプリセットと、`times: 1` のモックのプリセットを、MCP で有効にして試しました。試していないものは次の 2 つです。

- iPhone での `resolve` と `modify_headers` のプリセット。
- アプリの接続が開いたまま（HTTP/1 の使い回し、HTTP/2）`map_remote` や `resolve` のプリセットを有効にしたときの HTTPS。アプリは前に開いた接続を使い続けることがあります。

<a id="security-presets"></a>

<details>
<summary>セキュリティの詳細：これらのプリセットが別の場所へ送れるものと、無効になったあとに残るもの</summary>

要点は [SECURITY](SECURITY.ja.md#map_remotemodify_headersresolve-のプリセット) にあります。これらの種類のプリセットは、アプリが受け取るものだけでなく、リクエストの行き先や中身も変えます。

- 記録しているすべてのデバイスが対象になります（LAN モードでは、許可したすべてのアドレス）。`map_remote` のプリセットは、そのすべてから来る一致したリクエストを、リクエストに入っているものごと送り先へ送ります。
- 最悪の場合は、サイトが記録に書き込んだ文にエージェントが誘導され、本番の認証情報が、プリセットに書いたステージングや開発のサーバーへ何度も送られることです。エージェントが選べるのは、いつ有効にするかと、有効にし直して続ける長さだけです（送り先は選べません）。
- **無効になったあとに残るもの。** 有効な間にアプリが書いたもの（注文、編集）は、送り先のサーバーに残ります。アプリはそこで受け取ったトークン、Cookie、キャッシュを持ち続け、プリセットが無効になったあとで普段のサーバーに送るかもしれません。
- `resolve` はより安全な種類です。名前の接続先を別の場所にしますが、Host、SNI、TLS の検証は、その名前のままです（コードから判断したものです）。HTTPS では接続先のサーバーにその名前の証明書が必要です。
- `modify_headers` のプリセットが変えるのは、リクエストだけです。レスポンスに対するもの（`~s`）は、読み込みで断ります。ページの保護（CSP、HSTS）を外したり、Safari が表示するホストに Cookie を設定したりできてしまうからです。ヘッダーの値は表示しません。有効なプリセットは普通のルールのあとに当てるので、送られるのはプリセットのヘッダーです。
- **読み込みで断るもの。** 送り先を表示して確かめられるようにするためです。断るのは、[上](#map_remotemodify_headersresolve-のプリセット)に挙げた `map_remote` のプリセットです。ホストをリクエストから取るものや、このコンピュータと LAN のアドレス（`localhost`、`*.local`、プライベートアドレス）以外へ平文の `http://` で送るものがこれに当たります。
- **リクエストごとに確かめるもの。** 書き換えたあとの URL のスキーム、ホスト、ポートを、表示した送り先と照合します。正規表現が URL の途中に一致したリクエストには 502 を返し、別の場所へは送りません。
- **表示するもの。** 各プリセットの送り先（`map_remote`）やアドレス（`resolve`）を、`run` の準備完了の表示、ログ、`list_presets` に出します。有効なプリセットは `reqcove status` に出します。フィルター、正規表現、ヘッダーの値は出しません。プリセットが変えたフローには、`presets` にそのプリセットが出ます。Skill とサーバーの instructions は、そうしたフローの応答を普段のサーバーのものとして報告しないよう、エージェントに伝えています。
- `activate_preset` はどの種類のプリセットも有効にできます。読み取り専用の注釈はなく、そうしたツールの前に確認するクライアントは確認します。`"mcp__reqcove"` をまとめて許可したクライアントは、これも許可します。確認なしで許可すると、これらの種類も許可することになります（ガイドの[例](#ツールを許可する)では `ask` に入れています）。
- 上限と見え方はモックのプリセットと同じです。1 回につき最長 5 分で（これらの種類に `times` はありません）、このコンピュータでだけ使え、`--mcp-http` では使えません。読み直しや再起動で無効になり、2 つの時計で確かめます。
- **試していないこと。** プリセットが有効・無効になる前にアプリが開いていた接続（使い回される HTTP/1 や HTTP/2 の接続）を、アプリがどう扱うかは試していません。アプリは使い続けるかもしれません。その場合、切り替えがすぐには反映されなかったり、終わりの時刻を過ぎても続いたりすることがあります。
- **コードから判断したこと。** ルールはリクエストの始まりで当てます。そのため、`map_remote` や `resolve` のプリセットが有効な間に始まった WebSocket、ストリーム、長いアップロードは、プリセットが無効になったあとも、5 分を過ぎても、その送り先のままです。

確認状況：テスト（表示した送り先の外へ書き換えられた URL への 502。プリセットのヘッダーを普通のルールのあとに当てること）。平文の HTTP での E2E テスト（`resolve` が保つもの）。

</details>

#### ルールが当たった理由、当たらなかった理由（`list_rules`、`explain_rules`）

このコンピュータのエージェントはファイルを読まずにルールを確かめられます。

`list_rules` は、ルールを種類と番号（`rewrites` と同じ `mock[0]`）で返します。プリセットと有効かどうか、そしてルールから導いたものだけを一緒に返します。

| 種類 | `list_rules` が返すもの |
|---|---|
| `mock` | match と応答 |
| `map_remote` | 送り先のスキームとホスト（置き換えがパスなら `path only`、ホストを書いていなければ `not shown`） |
| `modify_headers` | ヘッダー名と向き（`~q` なら `request`、`~s` なら `response`、ほかは `both`） |
| `resolve` | 名前とアドレス |
| `map_local` | ルールの番号だけ |

フィルター、正規表現、ヘッダーの値、ボディ、ファイルのパスは返しません。

`explain_rules` は、リクエストがどのルールを受けたか（受けるか）と、その理由を返します。フローの id か、メソッドと URL（と GraphQL の operation）を渡します。

1. まず範囲を答えます。`--allow-hosts` にないホストと `--pass-hosts` のホストには、どのルールも当たりません。
2. 次に、作ったリクエストに本物のリクエストと同じコードを通します。送りはしません。返すのは、記録と同じ書き方の `rewrites`、`mocked`、`mapped_to`、いま有効で当たるプリセット、無効なプリセットを有効にしたらどうなるか（`if_turned_on`）です。

注意点は次のとおりです。

- ヘッダー、ボディ、レスポンスを読むフィルター（`~h`、`~b`、`~t`、`~c` など）は、メソッドと URL だけでは決められません。そのルールは当たらないものとして扱い、`cannot_tell` に入れます。
- フローの id を渡すと、そのフローが実際に受けたものを `recorded` に入れます。そのあとにルールやプリセットの状態が変わっていることもあります。
- プリセットの回数は使わず、有効・無効も変えません。
- 記録される URL はマスク済みです。パスやクエリでマスクした値（`[redacted]`）で、フィルターや正規表現の結果が変わることがあります。
- 本物のリクエストと同じく、URL にある GraphQL の operation が、渡したものより先に使われます。

確認状況：E2E テスト（平文の HTTP）で確認しました。確認したのは、`list_rules` がフィルター、正規表現、ヘッダーの値、ボディ、パスを返さないこと（目印の文字列で）、範囲外のホスト、`--pass-hosts` のホスト、モックのプリセットの無効と有効（回数を使わず、サーバーにも届かない）、operation の有無での GraphQL のモック、`cannot_tell` に入る `~h` のフィルター、`map_remote` のあとの `resolve` を記録されたフローと同じに説明すること、ルールのファイルがないときです。iPhone を使った確認の中で、Claude Code からも両方のツールを使いました（iOS 27.3、2026-11-14）。

<a id="security-rules"></a>

<details>
<summary>セキュリティの詳細：ルールを変えられるもの、ヘッダーのルールが届くホスト、ルールの接続先</summary>

要点は [SECURITY](SECURITY.ja.md#ルール--rules) にあります。`--mcp-http` 経由のエージェントには、ルールのファイルに届く手段がありません。

- `run --rules-reload` は、ファイルが変わるたびに読み直します。そのため、ファイルに書き込めるもの（あなたのユーザーとして動くプロセスなら何でも。ファイルを扱えるエージェントも含みます）は、`run` が動いている間に、デバイスのリクエストの行き先を変えられます。付けなければ、ファイルを読むのは mitmproxy の起動時だけです（`run` と一緒に起動するときと、mitmproxy が終了して Reqcove が起動し直すとき）。
- `reqcove mock add` は、あなたの代わりにモックをルールファイルに書きます。動くのは、入力と出力がターミナルのときだけです。これは、頼まれていないエージェントが実行するのを防ぐ助けで、保証ではありません（コマンドを実行できるエージェントは、ターミナルを用意することも、ファイルを直接編集することもできます）。ルールを書くのはあなたです。Skill はエージェントに、このコマンドを実行しないよう伝えています。先に `run` にファイルを確かめさせるために、このコマンドは状態ディレクトリ（0600、あなたのユーザー）から `run` の SOCKS5 のパスワードを読みます。`run` は指定されたファイルを確かめるだけで、取り込みません。
- **ルールが失敗したリクエスト**（たとえば、`map_remote` が不正なポートを作ったとき）には、元のまま送らずに 502 で応答します。置き換えがまったく成り立たない `map_remote` があると、`run` は起動時に止まります。
- **`modify_headers`** が受け付けるのは、HTTP のトークンであるヘッダー名と、改行も NUL も含まない値です（含むと、送信時に別のヘッダーが始まってしまいます）。値のファイルをあとのフローのために読み直したとき、改行や NUL が入っていれば、その値をそのフローのヘッダーから外します。
- **`resolve` の名前**はホスト名だけです。そのため、名前に含まれるものが制御文字としてログに出ることはありません。

**ルールが付けるヘッダーは、リクエストが指定したホストにだけ届きます。** リクエストの Host はアプリが書くもので、mitmproxy は、Host に何が書いてあっても、アプリが接続した先へ接続します。一方、ルール（`~d`）は Host を読みます。そのため、ルールが付けるヘッダー（`modify_headers`。プリセットも含みます）は、リクエストが指定したホストにだけ届きます。レスポンスに付けるヘッダーは、そのホストのレスポンスにだけ付きます。`map_remote` や `resolve` がリクエストを別の先へ送らないとき、ルールが働くのは、次のどれかが成り立つときだけです。

- アプリが接続したアドレスが、アプリの送った Host そのものである（Host は、どのルールよりも前に読みます）。
- HTTPS で、その Host が、mitmproxy がサーバーの証明書を照合する TLS の名前である。その名前の証明書を持たないサーバーには、リクエストが届きません。`--upstream-proxy` を通すときは、この条件は使いません。そのとき mitmproxy が検証するのはプロキシの証明書で、サーバーの証明書を検証するのはプロキシだからです。
- このコンピュータで Host を引いたアドレスの中に、アプリが接続したアドレスがある。

どれも成り立たなければ、リクエストはアプリが送ったまま進み、レスポンスもサーバーが送ったまま戻ります。その rewrites には、ルールを当てなかったことが出ます（条件は `explain_rules` が示します）。細かい点は次のとおりです。

- ルールが Host を変えても、こうしたリクエストにルールは働きません。ルール自身が書いた Host で、ルール自身を通してしまうからです（Host に対してトークンを付けるルールと、Host を接続先のアドレスに書き換えるルールの組み合わせ）。リクエストの行き先を変えるのは、`map_remote` と `resolve` の役目です。
- **パスだけを変えてホストを変えない `map_remote`** は、ほかの `map_remote` と同じようにリクエストを送り直します。このとき mitmproxy はそのホストの名前をこのコンピュータで解決して接続します。アプリが接続したアドレスには接続しません。そのため、ヘッダーのルールが働きます。
- **名前は IDNA の ASCII 形で比べます**（HTTP/2 の `:authority` はデコードされて届き、SNI はデコードされずに届きます）。İ、ı、ſ、K を含む Host（そのままでも、`xn--` 形でも）にはルールは働きません。大文字と小文字を区別しない `~d` が、それを別の ASCII の名前に一致させてしまうからです（`mysıte.com` を `mysite.com` に）。
- 名前解決には上限があります。名前ごとに専用のスレッドで引き、1 つの名前につき同時に 1 回、同時に引く名前は 16 個までで、答えは 30 秒保持します。リゾルバが止まっても、イベントループの executor は空いたままで、プロセスも終了できます。Host の名前解決に 3 秒を超えてかかったリクエストと、16 個の名前を引いている最中に来たリクエストは、ルールなしで進みます。
- **このコンピュータの名前解決はデバイスのものと食い違うことがあります**（Exit Node は `--dns` に問い合わせます。デフォルトは 1.1.1.1 です。CDN はリゾルバによって違う答えを返すことがあります）。そのときリクエストはルールなしで進みます。その名前の `resolve` ルールがあれば避けられます（コードから判断したもので、CDN では試していません）。ただし、`--upstream-proxy` は `resolve` を受け付けないので、上流プロキシを通すときは、ルールなしのままです。
- こうしたリクエストを、代わりに Host の先へ送ることはしていません。そうすると mitmproxy が自分で名前を引くことになり、このコンピュータと LAN に対する Exit Node の拒否をすり抜けるからです（mitmproxy のコードから判断したものです）。

**`map_remote` と `resolve` はこのコンピュータから接続します。** 接続先はルールが指定した場所で、このコンピュータと LAN も含みます。Exit Node がそれらのアドレスを拒否するのは、デバイス自身の接続についてです。ルールがあると、中継しているデバイスのアプリは、そのルールのホストへリクエストを送るだけで、ルールの送り先に届きます（Web ページも含みます）。

- `resolve` が受け付けるのは IPv4 アドレスだけで、引く必要のある名前は受け付けません。`0.0.0.0/8`、リンクローカル、マルチキャスト、予約済みの範囲、Tailscale の 100.100.100.100、クラウドのメタデータのアドレス 169.254.169.254 と 100.100.100.200 は断ります。`map_remote` は、与えられたものを何でも受け付けます。
- ポートのない `resolve` ルールはリクエストのポート（アプリのもの、または `map_remote` の URL のもの）を使います。
- `resolve` の送り先への TLS はルールの名前に対して検証します。使うのは mitmproxy 自身の CA の一覧です（certifi。mitmproxy のコードから判断したものです）。そのため、リクエストが進むのは、その名前の証明書を持つサーバーだけです。平文の HTTP は検証しません。
- `resolve` の名前には、それぞれ別のアドレスが必要です。mitmproxy は接続をアドレスごとに使い回すので、アドレスを共有する名前は、1 つの名前の検証を共有してしまいます。そのため、アドレスの共有は断ります。
- `resolve` の送り先のアドレスへの `map_remote` はその接続を双方向に共有します。一方のリクエストがもう一方のために作られて検証された接続に相乗りすることがあります。接続が失敗すると、アプリの接続が続く間、両方が失敗します。

**`mock` はサイトの名前で応答します。** アプリも、WebView のページも、それをサイト自身の応答として受け取ります。応答の中のスクリプトはそのオリジンで動き、リダイレクトにも従います。

- `mock` を使えるのは `--allow-hosts` のホストだけです（ほかは断ります）。ヘッダーの値は `modify_headers` と同じように確かめます。
- 記録には、フローがモックされたことと、ルールの番号とステータスが出ます。モックの中身は出ません。
- モックが応答するかもしれないリクエストは、ボディが届き終わるまで全体を保持します（operation がボディに入っているからです）。長さを示しているリクエストでは、1 MiB までです。
- 長さを示さない GET を保持するのは、ボディがない間だけです。HTTP/2 ではボディを送ってきた GET に、ボディの最初のバイトで 502 を返し、ボディは保持しません。これは `map_local` と同じです。空の DATA フレームでストリームが終わる GET には、応答します。そのバイトかストリームの終わりを待つ間、ボディは保持せず、サーバーにも接続しません（コードから判断したものです）。
- 12.3.1 以外の mitmproxy（別の `--mitmproxy-spec`）では、ヘッダーと同時に終わらないストリームに、すぐ 502 を返します（コードから判断したものです）。

**`list_rules` と `explain_rules` は読み取り専用です。**

- 示すのは、[上の表](#ルールが当たった理由当たらなかった理由list_rulesexplain_rules)のとおり、ルールから導いたものだけです。`map_remote` のルールが送り先を書いていないときは「path only」か「not shown」を、`map_local` のルールは番号だけを示します。フィルター、正規表現、ヘッダーの値、ボディ、ファイルのパスは示しません。
- `explain_rules` は、自分で作ったリクエストに対して、リクエストの経路と同じコードを動かします。そのリクエストは送りません。プリセットの状態はコピーを使うので、プリセットの回数を使わず、プリセットを有効にも無効にもしません。
- プリセットのツールと同じく、この 2 つは `run` のローカルのソケットと `reqcove mcp` でだけ使えます。`--mcp-http` では使えません。送り先から、デバイスのリクエストをどこへ送れるかが分かるからです。

確認状況：上の各項目はテストで確かめています。ルールが付けるヘッダーがどのホストに届くかは、本物の mitmproxy と代役のサーバーを使ったテストで確かめました（平文の HTTP と HTTPS、リクエストとレスポンスの両方向）。次の点には限りがあります。

- ネットワークを通さずに確かめたもの：IDNA と İ、ı、ſ、K（mitmproxy 自身が作ったフローで）、名前解決の上限（mitmproxy の Python で、答えが返らない名前解決を使って。動いている mitmdump では確かめていません）、パスだけを変える `map_remote`（mitmproxy の Python で）。
- 502 と空の DATA フレームは Go の HTTP/2 クライアントだけで確かめました。mitmproxy がストリームの終わりをどう伝えるかは、mitmproxy のコードから判断したものです。
- `resolve` の送り先が別の名前の信頼された証明書を持つときに 502 になることは、手で試しました。

</details>

### 上流プロキシに回す（`--upstream-proxy`）

Reqcove で記録しながら、同じリクエストを Burp Suite や ZAP、Charles などでも見たいときに使います。

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' \
  --upstream-proxy http://127.0.0.1:8080
```

復号したリクエストはプロキシへ送り、サーバーへは直接接続しません。HTTPS は CONNECT トンネルで、平文の HTTP はプロキシ宛てのリクエストとして送ります。プロキシにはマスクされていない中身がすべて見え、Burp はそれをプロジェクトに保存します。Burp の Intercept はオフにしてください。オンのままだと、リクエストがそこで止まります。

- `--allow-hosts` にないホストへの接続はこれまでどおり直接通ります。ただし、HTTP/2 の接続の再利用で、許可したホストへの復号済みの接続に相乗りしたほかのホスト宛てのリクエストは、記録されないままプロキシを通ります。許可したホストへのほかのプロトコル（MQTT など）は、サーバーへ直接接続します。TLS を使うものは、プロキシの CA を使っている間は失敗します（サーバーの証明書を、その CA で検証するためです）。
- Burp は HTTPS のホストに、SNI の名前をこのコンピュータで名前解決し直して接続します。そのため、Exit Node がこのコンピュータと LAN を宛先として拒否していても、その拒否は Burp の接続先には働きません（[セキュリティの詳細](#security-upstream-proxy)）。`--allow-hosts` は、調べるホストだけにしてください（`'*'` のときは `run` が警告します）。同じ理由で、`resolve` のルールは拒否します。プロキシ側の設定（Burp の Hostname resolution overrides）を使ってください。
- プロキシを通る HTTPS はプロキシの CA だけで検証します。このコンピュータの Burp の CA は、起動時に Burp のプロキシのアドレスにある `/cert` から取得します。ほかの復号するプロキシ（ZAP、Charles など）には、`--upstream-ca FILE`（PEM か DER）で CA を指定してください。どちらでもなければ、公開の CA で検証します（復号しないプロキシ向け）。このコンピュータで Burp 以外のプロキシを使うときも、`run` は起動時にそのプロキシのアドレスにある `/cert` を取りに行きます。そこで失敗しますが、動きは変わりません。
- Reqcove はプロキシに直接接続し、システムのプロキシ設定は使いません。ただし、システムのプロキシを自分に向けるプロキシ（Charles は、Proxy メニューの「macOS Proxy」をオフにしない限りそうします）と `--local-proxy` は、同じ設定を取り合い、止まるときに相手の設定へ戻してしまいます。`--local-proxy` と一緒に使うときは、プロキシ側のその機能をオフにしてください。
- Burp での動作：平文の HTTP は IP アドレスで表示され、名前は `Host` ヘッダーで分かります。リクエストのボディは、すべて届くまで Burp が保持します。HTTP/1.1 のクライアントへの Server-Sent Events は失敗します（iOS アプリの多くが使う HTTP/2 では流れます）。SNI のない、IP アドレス宛ての HTTPS は失敗します（Burp が証明書に入れるアドレスの形式を、mitmproxy が受け付けないためです）。`--web` と一緒に使うと、mitmweb からリプレイした平文の HTTP リクエストは、プロキシ自身に送られます。

確認状況：Burp Suite Community 2026.10 で確認しました（SNI の名前で名前解決し直すことを含みます）。Charles 5.0b12（復号する設定）でも、`--upstream-ca` を付けて確認しました（付けないと、証明書を信頼できなかったことが記録に残ります）。試していないもの：ほかのプロキシ。ほかのプロトコルがサーバーへ直接接続することは、コードから判断したものです。

<a id="security-upstream-proxy"></a>

<details>
<summary>セキュリティの詳細：プロキシに見えるもの、証明書を検証する側、プロキシの接続先</summary>

要点は [SECURITY](SECURITY.ja.md#上流プロキシ--upstream-proxy) にあります。そのほかの点は次のとおりです。

- Reqcove の mitmproxy は、自分ではサーバーに接続しません（connection strategy は lazy です）。許可したホストへの TLS 上のほかのプロトコルは、それでもサーバーへ直接進みます（コードから判断したものです）。このフラグは起動時に読みます。これを変えるツールはありません。
- Burp 自身の MCP サーバーや拡張は、Reqcove のツールが渡さないものと、リクエストを送る手段をエージェントに与えます。
- 本物のサーバーの証明書を検証するのは、プロキシの仕事です。プロキシの CA（`--upstream-ca` で指定したもの、または起動時に取得した Burp のもの）があるとき、Reqcove が信頼するのはその CA だけです。つまり、Reqcove が検証するのはプロキシで、サーバーではありません。試したところ、Burp はデフォルトではサーバーの証明書を検証しませんでした。
- Burp の CA は平文の HTTP で取得します。取得元はプロキシ自身のリスナー（`http://127.0.0.1:PORT/cert`）です。名前を引かないので、ほかのサーバーは応答できません。取得するのはプロキシがこのコンピュータにあるときだけで、受け入れるのは「PortSwigger CA」という名前の CA だけです。
- プロキシがどこに接続するかは、プロキシが決めます。Reqcove は、Exit Node が許可したアドレスをプロキシに渡します。しかし Burp は SNI の名前をこのコンピュータでもう一度引いて接続します。
- `--allow-hosts` を狭くしておく理由は次のとおりです。iPhone が開いたサイトは DNS リバインディングで、プロキシが名前解決するときだけ、自分の名前をこのコンピュータの LAN に向けられます（コードから判断したもので、試していません）。`resolve` のルールを `--upstream-proxy` と一緒に使うと断るのも、このためです。
- CONNECT の行（IP アドレスとポート）と平文の HTTP は暗号化されずにプロキシに届きます。プロキシはこのコンピュータか tailnet に置いてください。

確認状況：テスト（サーバーへの接続を数えるテスト。「PortSwigger CA」という名前の CA だけを受け入れること）。Burp で試しました。Burp は `/cert` で応答し（curl で確かめました）、デフォルトではサーバーの証明書を検証せず、SNI の名前で接続しました。

</details>

## Tailscale を使わずに同じネットワークでつなぐ（`--lan`）

`reqcove run --lan` は tailnet のノードを起動しません。Reqcove はこのコンピュータの LAN のアドレスで HTTP プロキシとして待ち受け、同じネットワークの iPhone が Wi-Fi のプロキシ設定にこれを指定します。主な使い方は今後も Exit Node です。Exit Node は iPhone のすべての通信をモバイル通信でも中継し、つながっているネットワークに何も求めません。LAN モードは Tailscale を使えないときのためのものです。

```sh
reqcove run --lan --allow-hosts api.example.com
```

1. `run` が待ち受け先を表示します。デフォルトルートのインターフェイスのアドレス（別のものは `--lan-interface en0` で指定。VPN のトンネルは不可）と、`--proxy-port`（デフォルトは 8080）です。
2. iPhone で、設定、Wi-Fi、ネットワークの (i)、プロキシを構成、手動の順に開き、そのサーバーとポートを入力します。認証はオフのままにします。
3. このコンピュータで iPhone を許可します。最初の接続は拒否され、`run` がそのアドレスをログに出します。`run` の質問に答えるか、ターミナルで `reqcove lan allow ADDR` を実行します。質問（`Allow ADDR? [y/N]`）は、`run` がターミナルのフォアグラウンドのジョブのときに出ます。
4. CA を信頼します（デバイスごとに 1 回）。Exit Node のときと同じく、プロキシを設定した状態で `http://mitm.it` を開きます。平文の HTTP は同じ LAN のほかの人に差し替えられるおそれがあります。そのため、`run` の準備完了の表示には AirDrop で送るための CA のファイルと、照合するための CA の SHA-256 も出ます。SHA-256 は iOS の表示と同じ形（小文字の 2 桁ずつ、空白区切り：`ab 90 7e …`）です。iPhone では設定、一般、VPN とデバイス管理、そのプロファイル、詳細で見られます。そのファイルを AirDrop で送ることは試していません。

`reqcove lan list` で許可したアドレスと許可した日時を表示し、`reqcove lan deny ADDR` で許可を取り消します。`reqcove lan` のコマンドはターミナル以外では動きません。エージェントが使うものではありません。

記録と `reqcove status` では次のように見えます。

- 記録では、デバイスは `lan:ADDR` という名前になります。ツールの `device` での絞り込みと `reqcove har --device lan:ADDR` はこの名前を受け付け、`list_devices` はこの実行での最初と最後のリクエストの時刻を返します。
- `reqcove status` と `status` ツール（`mode: "lan"`）には、待ち受け先、許可したアドレス、この実行で拒否したアドレスが出ます。拒否したアドレスは同じネットワークの誰でも増やせるので、最後に見た 50 件と、残りの件数（`refused_more`）だけを出します。元の一覧は最大 10,000 件で、いっぱいになると空にします。

パスワードはありません。誰がプロキシを使えるかは、Charles Proxy と同じく、このコンピュータでアドレスごとに決めます（Charles のドキュメントでは、アクセス制御のリストと、新しいアドレスへのダイアログが説明されています）。これは次のことを意味します。

- 許可するのはデバイスではなくアドレスです。あとでそのアドレスを持ったものも許可されます。同じプレフィックスの別のネットワークでも同じです（[セキュリティの詳細](#security-lan)）。使い終わったら `reqcove lan list` と `lan deny` で整理してください。iPhone のプライベート Wi-Fi アドレスが同じネットワークで長く変わらないかは、確かめていません。
- 許可したアドレスはこのコンピュータを通って、あなたのアドレスからインターネットに出られます（80 番と 443 番ポートのみ）。`--allow-hosts` に完全な名前（`*` なし）で書いたプライベートなホストにも届きます。このコンピュータの VPN の先のものも含みます。このコンピュータ、リンクローカルアドレス、プロキシのあるネットワークには、完全な名前でも届きません。許可したホストへのリクエストは記録されます。
- `lan deny` は 2 秒以内に新しい接続を拒否しますが、すでに開いている HTTPS のトンネルは閉じるまで（または 15 分間やりとりがなくなるまで。[制限事項](#制限事項)）続きます。
- 信頼できるネットワークで使い、使い終わったら止めてください。

Exit Node とのほかの違いは次のとおりです。

- 80 番と 443 番ポートのみです。プロキシを設定している間は、このコンピュータや同じ Wi-Fi の開発サーバー（8081 番の Metro など）は拒否されます。iOS がローカルのアドレスにプロキシを使わないかは、確かめていません。
- 名前解決はこのコンピュータのリゾルバで、`/etc/hosts` が先です。そこで 127.0.0.1 になる名前は拒否されます。
- Wi-Fi のプロキシ設定に従わないアプリは直接インターネットに出て、記録されません。
- つながらない原因：Wi-Fi のクライアント分離（ゲスト用のネットワークによくあります）、iPhone とこのコンピュータの間の VLAN、MDM のプロファイル、管理されたファイアウォール。macOS のファイアウォールが `reqcove` への接続の許可を求めるかは、確かめていません。
- `--lan` は `--config` では使えないので、サービスとしては動きません。`--device`、`--ui`、`--mcp-http`、`--hostname`、`--dns` は tailnet のノードのものなので一緒に使えません。`--local-proxy` と `--web`（このコンピュータでのみ）は使えます。
- 同じネットワークでこのコンピュータのアドレスが変わると、新しいアドレスで待ち受けます。別のネットワークに移ると待ち受けをやめ、ログと `reqcove status` にそう出します。再起動すると新しいネットワークで待ち受けます。

確認状況：ループバックのインターフェイスで本物の mitmproxy を使ったテストで、HTTP と HTTPS が記録されること、`http://mitm.it` が CA を返すこと、上の拒否を確かめました。自宅の Wi-Fi の iPhone（iOS 27.3、2026-11-14）で試したのは、上の 4 つの手順（Safari の HTTPS の記録と SHA-256 の照合を含みます）と、`reqcove lan deny` のあとの再度の `lan allow` です。Linux（VM、2026-11-14）では、VM を動かしている Mac から curl で、iPhone なしで、許可と拒否、HTTP と HTTPS の記録、ポート 22 の拒否を試しました。試していないもの：ネットワークの切り替え、Linux のコンピュータと iPhone の組み合わせ。

<a id="security-lan"></a>

<details>
<summary>セキュリティの詳細：拒否する接続、拒否に変えたときの動き、許可したアドレスが届く先</summary>

要点は [SECURITY](SECURITY.ja.md#lan-モード--lan) にあります。そのほかの点は次のとおりです。

- 待ち受けるのは、このコンピュータのアドレスの 1 つ、つまり LAN のインターフェイス 1 つのアドレスです。ポートは `--proxy-port` です。0.0.0.0 でも、VPN のトンネルでも待ち受けません。
- 許可したアドレスの一覧は、ネットワークが変わっても残ります。一覧は状態ディレクトリに保存するので、同じプレフィックスを持つ別のネットワークでも、そのアドレスは許可されたままです（カフェの 192.168.1.0/24 と自宅の 192.168.1.0/24）。一覧は準備完了の表示、`reqcove status`、`reqcove lan list` で見られます。
- ほかのアドレスは拒否します。そのインターフェイスのネットワークの外からの接続は、受け付けた時点で閉じます。許可していないアドレスからの接続も同じです。何も記録せず、新しいアドレスごとに 1 回ログに出します。見たアドレスの一覧（10,000 件）がいっぱいになると、一覧を空にします。そのあとは同じアドレスをもう 1 回ログに出し、`run` がもう一度尋ねます。
- 拒否に変えると、新しいリクエストは 2 秒以内に断ります。維持している接続でも、リクエストごとにもう一度確かめるからです。すでに開いている HTTPS のトンネルは、閉じるまで続きます。どちらの向きにも 15 分バイトが流れなければ、そこで閉じます。1 つのアドレスが同時に開けるトンネルは、256 本までです。
- **許可したアドレス**は `<state>/lan-allowed` に保存します（0600。許可した日時も入ります）。一覧を変えられるのは、`reqcove lan allow|deny` と、`run` が自分のターミナルで出す質問だけです。一覧を変える MCP ツールはありません。
- `lan` コマンドは、標準入力と標準出力がターミナルでなければ断ります。`reqcove links` と同じです。エージェントのシェルはたいていどちらも持っていません。これは助けで、保証ではありません（スクリプトはターミナルを用意できます）。
- **`run` の質問**は、`run` がターミナルのフォアグラウンドのジョブである間だけ出します。質問の前に入力されたものは先に捨てるので、前に押した Enter や `y` は答えになりません。
- `--lan` は `--config` のファイルでは断ります。そのため、`brew services` と `reqcove service install`（インストール時にもそのファイルを断ります）が、開いたプロキシを動かし続けることはありません。

許可したアドレスがこのコンピュータを通して届く先は、次のとおりです。

| 行き先 | 届くかどうか |
|---|---|
| 80 番と 443 番以外のポート | 届きません。名前解決の前に拒否します |
| 公開のアドレス | 届きます。あなたのアドレスから出ていきます |
| プライベートな範囲（10/8、172.16/12、192.168/16、100.64/10）。このコンピュータの VPN の先も含みます | `--allow-hosts` に完全な名前（`*` なし）で書いたものにだけ届きます |
| このコンピュータ（ループバック、自身のアドレス）、リンクローカルアドレス、プロキシのあるネットワーク、公開のアドレス空間から番号を振った、このコンピュータのほかのネットワーク、特殊用途の範囲、IPv6 | 完全な名前を書いても届きません |

- 名前はこのコンピュータのリゾルバで引きます。`/etc/hosts` が先です。
- `--rules` の `map_remote` と `resolve` の送り先には mitmproxy が接続するので、上の確認の外です。許可したホストをこのコンピュータのサーバーに送るルールがあると、LAN のクライアントのリクエストもそこに届きます。
- `http://mitm.it` の CA は平文の HTTP で届くので、LAN のほかの誰かが差し替えられます。AirDrop で送るための CA のファイルと、プロファイルの「詳細」（More Details）と照合するための SHA-256 を表示するのは、このためです（上の手順 4）。

確認状況：テスト（拒否する接続とアドレスのログ。拒否への変更、使われていないトンネル、256 本のトンネルは、小さい値で確かめました。許可したアドレスが届く先。`run` の質問はターミナルの呼び出しを差し替えて確かめたもので、ターミナルの呼び出しそのものはテストしていません）。自宅の Wi-Fi の iPhone で試しました（2026-11-14）。許可するまで拒否され、そのあと記録され、`reqcove lan deny` のあとはまた拒否されました。SHA-256 は iOS の表示と一致しました。

</details>

## サービスとして動かす

ログインしたら `run` を起動させる方法は 2 つです。Homebrew で入れた場合は Homebrew の `brew services`、リリースのバイナリやソースからビルドしたものなら `reqcove service install` です。`--lan` はどちらでも断ります（[LAN モード](#tailscale-を使わずに同じネットワークでつなぐ--lan)）。

### 常駐させる（`brew services`）

ログインしたら `run` を起動させるには、フラグを 1 行に 1 つずつファイルに書き、`brew services` で起動します。先に注意：Mac がスリープしている間、Exit Node を使っている iPhone はインターネットにつながりません。スリープする前に Exit Node をオフにしてください。

```sh
mkdir -p "$(brew --prefix)/etc/reqcove"
printf -- '--device iphone\n--allow-hosts api.example.com\n' > "$(brew --prefix)/etc/reqcove/config"
chmod 600 "$(brew --prefix)/etc/reqcove/config"
brew services start reqcove
reqcove links        # 初回はログイン用の URL（1 分ほど待つ：初回は mitmproxy を取得する。tail -f "$(brew --prefix)/var/log/reqcove.log"）
reqcove status       # 「service: sh.brew.reqcove」と出る（古い Homebrew では homebrew.mxcl.reqcove）
```

- ファイル：`--config FILE` は `run` のフラグを 1 行に 1 つずつ読みます。
  - `#` から後ろはコメントです。シェルと同じように引用符でくくれます：`--device "Taro's iPhone"`。`~/` はホームディレクトリです。サービスは `/` で起動するので、パスはフルパスか `~/` から書きます。
  - コマンドラインのフラグはファイルのあとに読むので、1 回だけ指定するフラグはコマンドラインのものが勝ち、繰り返せるフラグは足し合わされます。
  - ファイルで断るもの：`--no-redact`、`--web`、`--rules-reload`、`--lan`、`--config`、`--allow-hosts '*'`（`@FILE` で指定したものも）。これらはコマンドラインでだけ使えます。
  - ファイルは自分の持ち物で、自分だけが読めるもの（`chmod 600`）に限ります。`--mask-values` のパターンを書くことがあるためです。
  - `--config` は 1 つだけです。指定しなければ、何も読みません。
- 終わったとき：ファイルがないときや断ったときは、サービスは 1 回で終わります（`brew services` がエラーを表示します）。繰り返し起動し直すことはありません。ほかの理由で終わったときも同じなので、`brew services restart reqcove` で起動し直してください（`brew upgrade reqcove` のあとも）。
- ログ：`$(brew --prefix)/var/log/reqcove.log` です。状態ディレクトリの `mitmproxy.log` も伸び続けます。launchd も reqcove もローテーションしないので、ときどき空にしてください。どちらにもログイン用の URL やトークンは入りません。それらは `reqcove links` が自分のターミナルに表示します。
- ターミナルからの `run`：同じ状態ディレクトリで、ターミナルから `run` を起動すると「使用中」と断られます。先に `brew services stop reqcove` を実行してください。
- スリープ：`run` は動いている間、Mac のアイドルスリープを止めます（`caffeinate -i`。ターミナルから起動したときと同じで、バッテリーでも止めるので電池を使います）。ふたを閉じたときや、スリープを選んだときは止められません。

Linux では、Homebrew の `brew services` が同じ formula から systemd のユニットを作ります（Homebrew のドキュメントによるもので、試していません。`status` はサービスを表示しません）。Homebrew を使わないなら、次の節を見てください。

確認状況：設定ファイルの読み方と断るフラグは、単体テストで確認しました。macOS 27 では formula から `brew services start` と `stop` を試し、iPhone のリクエストが記録されました（ログにトークンやログイン用の URL は入らず、止めたあと `links` と `login-url` は消えました）。`brew services` で試していないもの：ログイン時や Mac の再起動後の起動、スリープ、ターミナルから起動していない `run` に macOS がローカルネットワークの許可を求めるか（この 3 つは、下の `reqcove service install` で試しました）。launchd のデフォルトの優先度で遅くならないかも試していません。

### Homebrew なしで常駐させる（`reqcove service install`）

リリースのバイナリや、ソースからビルドしたものなら、`reqcove service install` で同じことができます（Homebrew で入れたなら、上の `brew services` を使ってください）。macOS では LaunchAgent（`~/Library/LaunchAgents/io.github.mh-mobile.reqcove.plist`）、Linux では systemd のユーザーユニット（`~/.config/systemd/user/reqcove.service`）を作ります。サービスはこのバイナリ（フルパス）を `run --config FILE` で起動します。すぐに起動し、ログインするたびにも起動します。終わっても起動し直しません（`brew services` と同じ）。

```sh
mkdir -p ~/.config/reqcove
printf -- '--device iphone\n--allow-hosts api.example.com\n' > ~/.config/reqcove/config
chmod 600 ~/.config/reqcove/config
reqcove service install       # 別のファイルなら --config FILE、別の状態ディレクトリなら --state DIR
reqcove links                 # 初回はログイン用の URL（1 分ほど待つ）
reqcove status                # 「service: io.github.mh-mobile.reqcove」と出る（Linux では reqcove.service）
reqcove service restart       # 終わったあとや、ファイルを変えたあとに起動し直す
reqcove service uninstall     # 止めて、ファイルを消す
```

- ファイルは `--config` で指定しなければ `~/.config/reqcove/config` です。読み方は `brew services`（上）と同じです。
  - インストールのときに、ファイルがない（書き方を表示します）、自分の持ち物でない、ほかの人が読める、`--no-redact`、`--web`、`--rules-reload`、`--lan`、`--config` が書いてある、のどれかなら断ります。
  - `--allow-hosts '*'` は `run` が起動したときに断ります（サービスは 1 回で終わります）。
  - ファイルに `--state` があれば、それが状態ディレクトリです（フルパスか `~/` から）。状態ディレクトリは空か、新しいか、reqcove のものに限ります（`run` と同じ）。
- 終わったとき：`run` が終わると（エラー、断られたファイル、`kill`）、次のログインまで止まったままです。`reqcove service restart` で起動し直せます（`launchctl kickstart -k gui/$(id -u)/io.github.mh-mobile.reqcove` か `systemctl --user restart reqcove` を実行します。macOS では試していません）。
- Homebrew のサービスがあるときは断ります（ファイルがあるか、読み込まれている：`sh.brew.reqcove`、`homebrew.mxcl.reqcove`。Linux では `sh.brew.reqcove.service`、`homebrew.reqcove.service`。Linux の名前は Homebrew のコードから判断したもので、試していません）。2 つのサービスが同じ状態ディレクトリを取り合うためです。
- Homebrew で入れた `reqcove` も断ります。そのパス（Cellar の中）は `brew upgrade` で消えるためです。`reqcove setup` で Homebrew のサービスが読むファイルを書き、`brew services start reqcove` で起動してください。
- インストール済みのとき：起動し直すには `reqcove service restart` を実行します。コマンドラインのフラグを変えるときやバイナリを動かしたあとは、`reqcove service uninstall` のあとでもう一度インストールしてください。
- ログ：
  - macOS：状態ディレクトリの `service.log` です。ローテーションしないので、`mitmproxy.log` と同じく、ときどき空にしてください。launchd が作ると 0644 になるので、`service install` が先に 0600 で作ります（launchd では試していません）。
  - Linux：`journalctl --user -u reqcove` です。
  - ログイン用の URL やトークンは入りません。`service install` も表示しません。それらは `reqcove links` が自分のターミナルに表示します。
- `PATH` は、インストールしたときの uvx のディレクトリ、`~/.local/bin`、`/opt/homebrew/bin`、`/usr/local/bin`、システムのものの順です。ほかの場所にあるなら、ファイルに `--uvx /full/path/uvx` と書いてください。
- 次のログインまで止めるには、`launchctl bootout gui/$(id -u)/io.github.mh-mobile.reqcove` か `systemctl --user stop reqcove` を実行します。`reqcove status` がどちらかを表示します。
- ローカルネットワークの許可（macOS）：試したとき、macOS はスリープの前とあとに許可を求めました。その一覧には、別の場所に置いたビルドがそれぞれ別の項目として並びます。
- Linux：ユーザーユニットはログインしている間だけ動きます。`loginctl enable-linger $USER` がないと、最後のセッションが終わったときに systemd が止め（ssh では、最後にログアウトしてから 15 秒以内）、次のログインでまた起動します。linger があると、ログアウトのあとも動き続けます。ログインする前の起動時にも動きます（systemd のドキュメントによるもので、再起動は試していません）。

確認状況：単体テストで、書き出すファイル、断る場合、実行するコマンド、ログのパーミッションを確かめました（launchctl と systemctl は実行しません）。手作業では 2026-11-14 に試し、どちらの OS でもログにログイン用の URL やトークンは入りませんでした。macOS で試したのは、インストールからアンインストールまで（iPhone を記録）、スリープ、再起動後のログイン時の起動（ログイン時のアラートはなし）です。Linux（VM）では、ノードを tailnet にログインさせずに、インストールからアンインストールまで、`kill` のあとと `systemctl --user stop reqcove` のあとの `service restart`、linger のあるときとないときのログアウトを試しました。試していないもの：macOS での `service restart`、Linux での tailnet にログインしたノード、それを通したデバイスの記録、再起動。

<a id="security-config"></a>

### セキュリティの詳細

要点は [SECURITY](SECURITY.ja.md#フラグのファイル--config) にあります。

`run --config FILE`（`brew services` と `reqcove service install` のためのもの）は、`run` のフラグをファイルから読みます。つまり、そのファイルに書き込めるものが、次の起動のフラグを決めます。

- ファイルはあなたのもので、あなただけが読めるものでなければなりません（そうでなければ断ります）。`--mask-values` のパターンが入ることがあるからです。
- エラーが示すのは行で、値は示しません。
- 次の 5 つのフラグはファイルでは断ります。コマンドラインで指定してください。`--no-redact`（マスクを外します）、`--web`（通信をマスクなしで表示します）、`--allow-hosts '*'`（すべてのサイトを記録します。`@FILE` 経由でも断ります）、`--rules-reload`（動作中に、ファイルがリクエストの行き先を変えられるようにします）、`--lan`（LAN に開いたプロキシを作ります）。
- `--upstream-proxy` や `--rules` など、ほかのフラグはファイルに書けます。

確認状況：テスト（断る場合）。

<a id="security-logs"></a>

ログについては次のとおりです。

- 状態ディレクトリの `mitmproxy.log` に入るのは、mitmproxy のエラーの行だけです。
- `run` 自身の出力がファイルのときは、`run` が起動時に、最初の行を書く前にそのファイルを 0600 にします。リダイレクト先のファイルも、brew services の `$(brew --prefix)/var/log/reqcove.log`（launchd は 0644 で作ります）も対象です。
- `reqcove setup` は、サービスを最初に起動する前に brew のログを 0600 にします。`reqcove service install` も、自分の `service.log` を同じように 0600 にします。brew services では試していません。
- この出力にはトークンもログイン用の URL も入りません。入るのは、`run` がデバイスについてログに出すものです。

確認状況：テスト（失敗したリクエストや不正な形のリクエストで送ったシークレットが `mitmproxy.log` に届かないこと。`run` が出力を 0600 にすること。サービスのログを作ること）。

## コンテナで動かす

`reqcove run` はコンテナ（Docker、または Podman）でも動きます。手順、コンテナで違うこと、確かめたことは、別のページにあります：[コンテナで Reqcove を動かす](container.ja.md)。このガイドでコンテナに触れているのは次のところです。

- ほかのデバイスのエージェント：`--mcp-http` はコンテナでも同じフラグで、ポートの公開は不要です（[ほかのデバイスのエージェントから使う](#ほかのデバイスのエージェントから使う--mcp-http)）。
- ログイン用の URL とリンク：ターミナルでないところ（`docker logs`）では `run` は表示しません。`reqcove links` が表示します（[初回の起動](#初回の起動ログインと承認)）。
- セキュリティ：コンテナで変わることは [SECURITY](SECURITY.ja.md#コンテナで動かす場合) にあります。そこに書いていない点が 2 つあり、すぐ下に書いています。

<a id="security-container"></a>

- ターミナルを付けていないコンテナでは、`run` はログイン用の URL、リンク、トークンの代わりに `reqcove links` を案内します。
- `reqcove mcp` は `--log-driver none` で動かすので、ツールの答えはログに残りません。

確認状況：`scripts/container-smoke.sh`（状態ディレクトリの持ち主とモード。ネットワークは不要です）。攻撃を試して確かめたものではありません。

## うまくいかないとき

まず `reqcove status` を見てください。reqcove の状態と次の手順を表示します（エージェントには `status` ツールがあります）。そのうえで、起きていることから探してください。

| 起きていること | 説明のある節 |
|---|---|
| `run` は起動したが、手順が残っている（ログイン、Tailnet Lock、Exit Node の承認） | [初回の起動](#初回の起動ログインと承認) |
| ログイン用の URL や、トークン付きのリンクが表示されない（サービス、`docker logs`） | `reqcove links`：[初回の起動](#初回の起動ログインと承認) |
| `run` を止めたあと、iPhone の DNS が止まったままになる | [停止・再起動・アップデート](#停止再起動アップデート) |
| エージェントのツールが「動いていない」と答える、再起動のあと記録が空になっている | [停止・再起動・アップデート](#停止再起動アップデート) |
| ツールがバージョンの違いを伝える、`reqcove status` が Skill のバージョンの違いを伝える | [停止・再起動・アップデート](#停止再起動アップデート)、[Skill](#使い方を教える-skill-を入れるreqcove-init) |
| 通信は中継されるが、何も記録されない | [オプション](#オプション)の `--allow-hosts` |
| アプリのリクエストが失敗し、`reqcove status` がそのホストを表示する（証明書ピンニング） | [証明書ピンニングをするアプリを通す](#証明書ピンニングをするアプリを通す--pass-hosts) |
| Android のアプリが CA を拒否する | [Android を記録する](#android-を記録する) |
| gRPC のアプリの呼び出しが TLS の失敗として出る | [gRPC](#grpc) |
| 許可したホストの通信が見当たらず、`reqcove status` がその接続は raw TCP として中継されたと伝える | [HTTP として読まれない接続](#http-として読まれない接続raw-tcp) |
| `--local-proxy` で、`kill -9` や異常終了のあとこのコンピュータのアプリがつながらない、許可したホストがこのコンピュータのアプリでつながらない | [iOS シミュレーターを記録する](#ios-シミュレーターを記録する--local-proxy) |
| ルールが当たらなかった | [ルールが当たった理由、当たらなかった理由](#ルールが当たった理由当たらなかった理由list_rulesexplain_rules) |
| ルールのファイルが読み込めない、変更が反映されない | [ファイルを読み込むタイミング](#ファイルを読み込むタイミング--rules-reload) |
| `--upstream-proxy` で、リクエストが止まる、プロキシを通る HTTPS が失敗する | [上流プロキシに回す](#上流プロキシに回す--upstream-proxy) |
| mitmweb で、デバイスの HTTP(S) が止まった、ブックマークでトークンの入力を求められる | [mitmweb で見る](#mitmweb-で見る--web) |
| `--mcp-http` で、デバイスが拒否される、`429` が返る、Grok Bot の設定画面でコネクタが「エラー」と表示される | [ほかのデバイスのエージェントから使う](#ほかのデバイスのエージェントから使う--mcp-http) |
| LAN モードで、iPhone の最初の接続が拒否される、何かに妨げられてつながらない、別のポートの開発サーバーが拒否される | [LAN モード](#tailscale-を使わずに同じネットワークでつなぐ--lan) |
| Mac がスリープしている間、Exit Node を使っている iPhone がインターネットにつながらない | [常駐させる（`brew services`）](#常駐させるbrew-services) |
| サービスが終わったまま起動し直されない、ターミナルから起動した `run` が「使用中」と断られる | [サービスとして動かす](#サービスとして動かす) |
| ログに `did not answer within 10s (through mitmproxy)` や `the client left before … answered (through mitmproxy)` と出る | [制限事項](#制限事項) |
| reqcove が mitmproxy を再起動する、再起動が続いたあと `run` が止まる | [制限事項](#制限事項)（巨大な WebSocket のメッセージ）、[ルール](#ルールを書く--rules)（`map_local` のルールに合うホストへのとても大きなボディ） |
| IPv6、QUIC、通話 | [制限事項](#制限事項) |

この節はほかの節への案内だけです。試したことと試していないことは、それぞれの節に書いています。

## オプション

`reqcove run` のオプションは次のとおりです。

| | |
|---|---|
| `--device NAME` | 中継するデバイス。マシン名、デバイス名（タグのない自分のデバイスに限る）、tailnet の IP アドレス、StableID のいずれか。複数は繰り返して指定 |
| `--allow-hosts HOSTS` | 復号して記録するホスト。`api.example.com`、`*.example.com`（そのドメイン自身とすべてのサブドメイン）、すべてを対象にする `'*'`、または `@FILE`（1 行に 1 つ。`#` 以降はコメント）。指定しない場合、通信は中継するが記録しない |
| `--pass-hosts HOSTS` | 許可したホストのうち、復号せずに通すもの。書き方は同じ（`'*'` は不可）。[証明書ピンニング](#証明書ピンニングをするアプリを通す--pass-hosts) |
| `--rules FILE` | 許可したホストに適用する[ルール](#ルールを書く--rules) |
| `--rules-reload` | そのファイルが変わるたびに読み直す |
| `--proto FILE` | コンパイルした protobuf のスキーマ。[メッセージを名前付きで読む](#grpc) |
| `--upstream-proxy URL` | 復号したリクエストを[上流の HTTP プロキシ](#上流プロキシに回す--upstream-proxy)に回す |
| `--upstream-ca FILE` | そのプロキシの CA（PEM か DER） |
| `--local-proxy` | このコンピュータのアプリ用のプロキシ（`127.0.0.1:8082`）。[iOS シミュレーター](#ios-シミュレーターを記録する--local-proxy) |
| `--proxy-port N` | プロキシのポート。[Remote Proxy](#exit-node-を使わずに-wi-fi-のプロキシでつなぐ) のもの、`--lan` では LAN のプロキシのもの。デフォルトは 8080。0 で Remote Proxy を無効 |
| `--lan` | [LAN モード](#tailscale-を使わずに同じネットワークでつなぐ--lan)。tailnet のノードを起動せず、このコンピュータの LAN のアドレスで、許可したアドレス用の Wi-Fi のプロキシとして待ち受ける |
| `--lan-interface NAME` | `--lan` で待ち受けるインターフェイス。デフォルトはデフォルトルートのもの |
| `--ui` | [フローを見る読み取り専用のページ](#iphone-で見る--ui)。ノードの 80 番ポート |
| `--web` | mitmdump の代わりに [mitmweb](#mitmweb-で見る--web) を起動。マスクなし |
| `--mcp-http` | [MCP ツールを HTTP でも提供](#ほかのデバイスのエージェントから使う--mcp-http)。ノードの 8090 番ポート |
| `--dns SERVERS` | Exit Node が使う上流 DNS（カンマ区切り）。デフォルトは `1.1.1.1:53`（ポートは省略可）。`system` で `/etc/resolv.conf` の最初の nameserver |
| `--no-redact` | シークレットをマスクせずに記録 |
| `--mask-names a,b` | 名前がこれと一致するものもマスクする（表記の違いは問わない：`clientRef` は `client_ref`、`Client-Ref` にも一致。`X-Client-Ref` のように名前の一部の場合は一致しない）。ヘッダー、パラメータ、JSON のフィールド、GraphQL の引数、XML の要素と属性が対象。`@FILE` も可 |
| `--mask-values RE` | このパターン（RE2）に一致した部分を、どこにあってもマスクする。繰り返し指定するか `@FILE`（1 行に 1 つ）。シークレットそのものを書くなら、`ps` に出ないようファイルで、`\Q…\E` で囲んで |
| `--state DIR` | 状態ディレクトリ。デフォルトは `~/.reqcove`。ノードキー、CA とその秘密鍵を保存。新しいか空のディレクトリ、または reqcove が以前使ったものに限る。`--state ~/x` とスペースを空けて指定（`--state=~/x` は拒否）。CA のないディレクトリには `~/.reqcove` の CA をコピーし（写した先は `~/.reqcove/ca-copies` に記録し、`~/.reqcove` の `cleanup` が表示する）、`reqcove-NAME` という名前の新しいディレクトリでは、ノード名もそれになる：[複数の Exit Node](several-exit-nodes.ja.md) |
| `--hostname NAME` | ノードの名前。デフォルトは `reqcove`。状態ディレクトリに保存 |
| `--verbose` | tsnet のバックエンドと、フローごとの判断をログに出力 |
| `--config FILE` | [`run` のフラグをファイルから読む](#常駐させるbrew-services)。1 行に 1 つ。コマンドラインのフラグより先に読む（`--no-redact`、`--web`、`--rules-reload`、`--lan`、`--config`、`--allow-hosts '*'` は不可）。ファイルは `chmod 600` |
| `--uvx PATH` | 使用する uvx。同じ場所の `uv` が、デフォルトの mitmproxy を Reqcove のロックファイルから起動する（ハッシュを確認）。ファイル名が `uvx` でないパスは uvx として実行する（ロックもハッシュの確認もなし） |
| `--python VERSION` | mitmproxy を動かす Python。デフォルトは 3.14 |
| `--mitmproxy-spec SPEC` | ロックした `mitmproxy==12.3.1` 以外の mitmproxy。uvx で取得する（ロックもハッシュの確認もなし） |

ほかのコマンドは次のとおりです。`init`、`version`、`setup`、`service restart`、`service uninstall` 以外は、`--state DIR` も指定できます。

| | |
|---|---|
| `reqcove status` | reqcove の状態と次の手順。`--json` で `status` ツールの JSON を出力（答える run がないときは、標準出力には何も出さず、終了ステータス 1 で、理由を標準エラーに出します）。`--uvx PATH` |
| `reqcove links` | ログイン用の URL と、`--ui`、`--web`、`--mcp-http` のリンクを QR コード付きでもう一度表示。出力先がターミナルのときだけ（[初回の起動](#初回の起動ログインと承認)） |
| `reqcove mark` | `[TEXT]`（`-` で始まるものは `-- TEXT`）。記録の中に、あなたの（`cli`）[マーカー](#マーカーを置くreqcove-mark)を置く。ターミナルでのみ |
| `reqcove mock add` | `--rules FILE --url URL` とモックのフラグ。[ファイルにモックを足す](#ターミナルからモックを足すreqcove-mock-add)（確かめてから）。ターミナルでのみ（`--print` での表示はどこでも）。`--uvx PATH` |
| `reqcove mcp` | このコンピュータのエージェント用の MCP サーバー |
| `reqcove lan` | `allow ADDR`、`deny ADDR`、`list`。[LAN モード](#tailscale-を使わずに同じネットワークでつなぐ--lan)で中継するアドレス。ターミナルでのみ |
| `reqcove har` | [フローを HAR ファイルに出力](#har-ファイルに書き出すreqcove-har)。`--host`、`--device`、`--since`、`--until`、`--status`、`--method`、`--user-agent`、`--limit N` |
| `reqcove init` | [エージェント用の Skill](#使い方を教える-skill-を入れるreqcove-init)。`--client NAME`、`--print`、`--uninstall` |
| `reqcove setup` | [初回の手順](#初回の起動ログインと承認)。フラグなし。ターミナルでのみ |
| `reqcove service install` | `--config FILE`、`--state DIR`。そのあとは `reqcove service restart`、`reqcove service uninstall`。[Homebrew なしで常駐させる](#homebrew-なしで常駐させるreqcove-service-install) |
| `reqcove cleanup` | 元に戻す手順の表示。`--delete-state`、`--hostname NAME` |
| `reqcove version` | バージョンの表示 |

iPhone で確認したもの：`--mask-names`、RoamRun で操作したあとの `wait_for_flows`、試験用アプリでの `diff_flows`（二重に送ったリクエスト）、`list_ws_messages`、`--proto`。テストだけで確かめたもの：`--mask-values`、`max_body`、`--mcp-http` の回数制限、`multipart/form-data`、XML のボディ（mitmproxy を通した SOAP のリクエストの E2E テストも）。

コードから判断したもの（フラグのヘルプに基づく記述で、このガイドでは試していません）：`--proxy-port 0`、`--hostname`、`--verbose`、`--uvx`、`--python`、`--mitmproxy-spec`。`status --json` は、Ubuntu での LAN モードの確認で使いました。答える run がないときの終了ステータス 1 は、単体テストで確かめました。

## MCP ツール

| ツール | |
|---|---|
| `list_flows` | フローを新しい順に一覧。デバイス、ホスト（サブドメインを含む）、時間（`since: "10m"`）、ステータスコード（`404`、`4xx`、`none`）、メソッド、User-Agent（アプリ名など、含まれる文字列で指定。アプリのバンドル ID は通信に含まれない）、GraphQL の operation（`operation: "Login"`。`operationName`、なければ文書の最初の operation。一覧の行にも出る）で絞り込み。ページング対応。ホストが 1 件も一致しないときは、記録にある似たホスト（`acmeshop.com` に対する `acme-shop.com` など）を `similar_hosts` で返す |
| `search_flows` | URL とヘッダーのテキストを検索（`bodies` を指定するとボディの先頭も対象）。絞り込みと `similar_hosts` は同じ |
| `wait_for_flows` | デバイスでの操作が送った通信を読む。操作の前に `list_flows`（または `capture_stats`）の `checkpoint` を控え、操作のあと `after: checkpoint` で呼ぶ。それ以降に返事（レスポンスかエラー）が来たフローを、返事の早い順に返す。まだなければ、最初の 1 件を最長 `timeout` 秒（デフォルト 20、最大 30）待つ。結果の `after` を次の呼び出しに渡せば、同じフローは二度返らない。絞り込みは同じ。WebSocket は開いたとき（`101`）に一度だけ返り、閉じるまで `open` のまま |
| `get_flow` | フローを 1 件取得。ボディは `bodies` を指定したときだけ（`max_body` を指定すると、それぞれそのバイト数まで）。`response_trailers` は HTTP/2 のトレーラー（gRPC-Web では最後のフレーム）。`view` のあるボディは Reqcove が書き起こしたもので、バイト列そのものではない。protobuf（[gRPC](#grpc)）や、パートごとにマスクしてファイルは大きさだけにした `multipart/form-data` |
| `list_ws_messages` | WebSocket のメッセージを古い順に読む。テキストのメッセージは先頭 4 KiB をマスクして返し、ほかは大きさだけを返す（[残すメッセージと `after` の使い方](#websocket-のメッセージlist_ws_messages)） |
| `diff_flows` | 2 つのフローを比べる（成功したものと失敗したものなど）。メソッド、URL、ステータスコード、エラー、ヘッダー（名前ごと）、ボディ（JSON はパスごと）。マスク中は、両方でマスクされた値を「同じ」とは言わず `masked` に並べ（元の値は違うかもしれない）、テキストでないボディは比べない。`--no-redact` のときは全部比べる |
| `summarize` | ホスト、User-Agent、ステータスコード、メソッド、デバイス、Content-Type、gRPC のステータス（`by_grpc_status`）、エンドポイントごとの件数。エンドポイント（`by_endpoint`）は、メソッド、ホスト、クエリを除いたパス（ID は `{id}`）、GraphQL なら operation（`GET api.example.com/v1/users/{id}`、`POST api.example.com/graphql Login`）。絞り込みと `similar_hosts` は同じ |
| `list_devices` | 中継しているデバイス（LAN モードでは `lan:ADDR`）と、それぞれの件数、この実行での最初と最後のアクティビティ |
| `list_tls_failures` | デバイスが拒否した TLS ハンドシェイク。多くは証明書ピンニングか、まだ信頼されていない CA が原因 |
| `list_passthrough` | 運ぶものがフローとして記録されない接続。`reason` 付きで、`--pass-hosts` のホストへの接続（`pass_hosts`）と、許可したホストへの接続のうち mitmproxy が HTTP として読まずに raw TCP として中継したもの（`raw_tcp`。クライアントに決まった ALPN 付き：[raw TCP](#http-として読まれない接続raw-tcp)）。ホスト、接続先サーバー、時刻、バイト数。URL や中身はなし |
| `capture_stats` | mitmproxy の状態、記録がカバーしている期間、ドロップ数 |
| `status` | モード（`tailnet` か `lan`。`lan` では許可したアドレスと拒否したアドレスも）、セットアップが完了しているか。未完了なら次の手順。有効にしたプリセット。すべての種類（`active_presets`。`kind` 付き。`--mcp-http` では出しません。プリセットのツールがないため） |
| `list_presets` | `--rules` のファイルの[プリセット](#エージェントが有効にできるプリセット)。すべての種類（`kind`）。モックの match と応答、`map_remote` の送り先、`modify_headers` のヘッダー名、`resolve` の名前とアドレス。有効か、無効になる時刻。ボディ、ヘッダーの値、フィルター、正規表現は返さない。`--mcp-http` からは使えない |
| `activate_preset` | どの種類のプリセットも有効にする。最長 5 分（`minutes`。モックは `times` で最大 20 件）。`wait_for_flows` 用の `checkpoint` と、同じ一致条件で無効にしたプリセットを返す。`--mcp-http` からは使えない |
| `deactivate_preset` | プリセットを無効にする。`--mcp-http` からは使えない |
| `list_rules` | `--rules` のファイルの[ルール](#ルールが当たった理由当たらなかった理由list_rulesexplain_rules)を種類と番号で。プリセットと、ルールから導いたもの（モックの match と応答、`map_remote` の送り先、`modify_headers` のヘッダー名と向き、`resolve` の名前とアドレス）。フィルター、正規表現、ヘッダーの値、ボディ、パスは返さない。`--mcp-http` からは使えない |
| `explain_rules` | フロー（`flow_id`）や、メソッドと URL が、どのルールを受けたか（受けるか）と理由。範囲、書き換え、モック、有効なプリセットと、無効なものを有効にしたらどうなるか。メソッドと URL だけでは決められないフィルターのルールは `cannot_tell` に。何も送らず、プリセットの回数も使わない。`--mcp-http` からは使えない |
| `add_marker` | [マーカー](#マーカーを置くreqcove-mark)を置く（`text` は 1 行で 80 文字まで、マスクする）。`id`、`time`（`since` 用）、`checkpoint`（`wait_for_flows` の `after` 用）を返す。デバイスの側は何も変わらない。`--mcp-http` からは使えない |
| `list_markers` | マーカーを古い順に（`since`）。`source` は `cli`（`reqcove mark`）か `mcp`（エージェント）。`--mcp-http` からは使えない |

### WebSocket のメッセージ（`list_ws_messages`）

`list_ws_messages` は、1 つの WebSocket のメッセージを読みます。対象は、一覧の行に `websocket_messages` があるフローです。

- 順序とページ：古い順に返します。`after` にはチェックポイントか、前のページの `after` を渡します。`direction`（`client`、`server`）と `text` で絞り込めます。
- メッセージの中身：テキストのメッセージは先頭 4 KiB を、ボディと同じく届いた時点でマスクして返します。バイナリのメッセージ、その接続で毎秒約 20 件を超えた分、マスクの仕組みで読めないテキストは、大きさだけを返します（[メッセージの中でマスクするもの](masking.ja.md#websocket-のメッセージ)）。
- 残すメッセージ：接続の最初の 5 件（認証のメッセージはたいていここに入ります）と新しい 100 件です。`after` より後でそれ以外のものの数は `missed` に出ます。`after` 自体がそれらの間にあるときは `missed_at_most` が付きます。このときは `after` より前のものも数に入っていることがあります。
- 接続の状態：`open` と `close`（コード、閉じた側）で分かります。
- ほかのツールとの関係：メッセージが届いても `wait_for_flows` は返りません。ただし、時間切れの答えに、その間にメッセージがあった接続が `websocket_activity` として並びます。`search_flows` は `bodies` を付けると、残したメッセージも探します。

## 制限事項

主な制限事項は [README](../README.ja.md#制限事項) にあります。そのほかの制限事項は次のとおりです。

- IPv6 は拒否します。アプリはすぐに IPv4 にフォールバックします。
- QUIC は Apple 宛てを除いてドロップするので、アプリは TCP にフォールバックします。判定はホストではなくアドレスで行うため、`--allow-hosts` にないホストの QUIC も、`--allow-hosts` を指定しないときの QUIC もフォールバックします。443 番以外のポートの QUIC はそのまま通し、記録しません。
- mitmproxy は WebSocket のメッセージを 1 つずつ、届ききるまで保持します。圧縮されたもの（permessage-deflate）は丸ごと展開します（mitmproxy のコードから判断したもの）。そのため巨大なメッセージが来ると、メモリを多く使います。Reqcove の 4 KiB の上限は、Reqcove が残す分にかかるもので、mitmproxy のメモリにはかかりません。圧縮されたメッセージは展開されたうえでマスクされて記録されます。
- mitmproxy がメモリ不足で落ちると、reqcove が再起動します。再起動しても 1 分以内に落ちることが 5 回続くと、`run` はエラーで止まります（終了ステータスは 1 で、Ctrl-C の 0 とは違います。サービスとして動かしていれば、失敗と表示されます）。
- reqcove が mitmproxy に渡す接続は、mitmproxy がサーバーにつながるのを待ちます。直接つなぐ接続がサーバーを待つのと同じく、最長 10 秒です。そのときログには `<アドレス>:<ポート> did not answer within 10s (through mitmproxy)` と出ます。先にアプリがあきらめたときは `the client left before <アドレス>:<ポート> answered (through mitmproxy)` と出ます。どちらも、そのときサーバーが遅かったか、このコンピュータから届かなかったということです。
- Remote Proxy、LAN モード、`--local-proxy` では、1 つのクライアント（アドレス 1 つ。`--local-proxy` では、このコンピュータのアプリすべてで 1 つ）が同時に開けるトンネル（CONNECT。HTTPS や WebSocket）は 256 本までです。それを超えると、どれかが閉じるまで 503 を返します。どちらの向きにも 15 分間バイトが流れないトンネルは閉じます。やりとりが続く WebSocket やイベントストリームは開いたままです。Exit Node 自身の接続にはどちらの制限もありません（コードから判断したもの）。
- Exit Node 経由の通話は試していません。
- 機能ごとの制限事項はそれぞれの節にあります：[`--ui`](#iphone-で見る--ui)、[`--web`](#mitmweb-で見る--web)、[`--local-proxy`](#ios-シミュレーターを記録する--local-proxy)、[LAN モード](#tailscale-を使わずに同じネットワークでつなぐ--lan)、[ルール](#ルールを書く--rules)、[上流プロキシ](#上流プロキシに回す--upstream-proxy)。

確認状況：圧縮された WebSocket のメッセージは、Go のクライアントとサーバーを使った E2E テストと、iPhone（iOS 27.3、2026-11-15）から圧縮を受け付けるサーバーへの接続で確かめました。再起動が続いたあと `run` が止まることは、終了し続ける mitmproxy の代役で試しました。10 秒の待ち時間は応答しないアドレスで試しました（実際のアプリで出た 2 件が遅かった理由はわかっていません）。トンネルの制限は 2 本と 300 ミリ秒のテストで確かめました。

## セキュリティ

Reqcove を信頼するかどうかを決めるための要点は、[SECURITY.ja.md](SECURITY.ja.md) にあります。オプションごとの注意は上の各節の「セキュリティの詳細」に書いています。それ以外の主な項目は次のとおりです。

- [記録するもの](SECURITY.ja.md#記録するもの)：`--allow-hosts` のホストだけで、Apple のホストは対象外です。[マスク](SECURITY.ja.md#マスク)：見つかるものと、見つからないものがあります。[拾えないもの](SECURITY.ja.md#拾えないもの)：記録が残らない接続です。
- [エージェントが読んだものの行き先](SECURITY.ja.md#エージェントが読んだものの行き先)：モデルの提供元に渡ります。ボディがエージェントに指示しようとすることもあります（[プロンプトインジェクション](SECURITY.ja.md#プロンプトインジェクション)）。
- [デバイスから届く範囲](SECURITY.ja.md#デバイスから届く範囲)：このコンピュータ、LAN、tailnet には届きません。
- [CA の秘密鍵](SECURITY.ja.md#ca-の秘密鍵)：状態ディレクトリと、そのバックアップにあります。デバイスはプロファイルを削除するまで、この CA をすべてのサイトについて信頼します。
- [ほかの人のデバイス](SECURITY.ja.md#ほかの人のデバイス)：その人の同意が必要です。[ほかのユーザーと共有するコンピュータ](SECURITY.ja.md#ほかのユーザーと共有するコンピュータ)、[`cleanup` のあとに残るもの](SECURITY.ja.md#reqcove-cleanup-のあとに残るもの)。
- [Exit Node の DNS](SECURITY.ja.md#exit-node-の-dns)（`--dns`）と、[コンテナ](SECURITY.ja.md#コンテナで動かす場合)。

このうち次の 5 つは、詳細をこの下に書いています。詳細に書いているのは、SECURITY.ja.md に書いていないことだけです。[Exit Node の DNS](#security-dns)、[デバイスから届く範囲](#security-reach)、[ほかのユーザーと共有するコンピュータ](#security-shared-computer)、[このコンピュータのほかのプロセス](#security-other-processes)、[mitmproxy 自身のコード](#security-mitmproxy-code)です。

<a id="security-dns"></a>

### Exit Node の DNS（`--dns`）

Exit Node を通して名前を解決できるデバイス、引いた名前が見える相手、偽の応答で得られるものは、[SECURITY](SECURITY.ja.md#exit-node-の-dns) にあります。そのほかの点は次のとおりです。

- Exit Node はそれを使うデバイスに DNS over HTTPS（Tailscale の PeerAPI）で応答します。tailnet のポリシーが Exit Node の利用を認めたピアには、どれにでも応答します（Tailscale のコードから判断したものです）。
- そのピアが問い合わせる上流は、あなたのデバイスと同じです。デフォルトでは `1.1.1.1` です。`--dns system` のときや、`--dns` に LAN のリゾルバを指定したときは、上流はルーターや会社のリゾルバになり、そのリゾルバしか知らない名前も引けます。
- このコンピュータから上流までの DNS が平文なのは、Exit Node でも Remote Proxy でも同じです。
- 経路の外から偽の応答を返すのは難しくなっています。問い合わせごとにランダムな ID とランダムなポートを使い、ほかのアドレスからの応答は捨てるからです。
- 偽の応答で向けた先のサーバーの証明書は、復号するホストでは mitmproxy が、ほかのホストではスマートフォン自身が確かめます。このコンピュータ、その LAN、ループバックを指す応答は、そこへのほかの接続と同じく拒否します。
- 名前を隠すには、ローカルの DNS over HTTPS の中継を `--dns 127.0.0.1:PORT` として使う方法が考えられます。これは試していません。

確認状況：テスト（このコンピュータ、その LAN、ループバックを指す応答を拒否すること）。`--device` に入っていないこのコンピュータに Exit Node が応答することは、試して確かめました。

<a id="security-reach"></a>

### デバイスから届く範囲

デバイスから届く範囲、Reqcove が拒否するもの、拾えないもの（あなたのネットワークの公開アドレス）は、[SECURITY](SECURITY.ja.md#デバイスから届く範囲) にあります。そのほかの点は次のとおりです。

- 経路を通してだけ届く公開のネットワーク（ルーターの先にあって、インターフェイスのサブネットではないもの）は拒否しません（コードから判断したものです）。
- ping（ICMP echo）にも同じ規則を使います。`--device` にないデバイスからの ping と、拒否するアドレスへの ping は捨てます。一覧にあるデバイスから公開アドレスへの ping には、このコンピュータから ping を打って応答します（コードから判断したものです）。
- デバイスの UDP のフローが続いている間（最後のパケットから 2 分、DNS では 30 秒）、そのフローを通して応答できるのは、送り先のアドレスとポートだけです。ほかから、このコンピュータのそのポートに届いたデータグラムは捨てます。

確認状況：テスト（`--device` にないデバイスと、一覧にあるデバイスの両方から 127.0.0.1 へ ping を送るテスト。このコンピュータからデータグラムを 1 つ送るテスト）。

<a id="security-shared-computer"></a>

### ほかのユーザーと共有するコンピュータ

ほかのユーザーを締め出す仕組みと、対象外のものは [SECURITY](SECURITY.ja.md#ほかのユーザーと共有するコンピュータ) にあります。そこに書いた 3 つのソケットは、MCP ツールのものと、mitmproxy の 2 つです。ほかのユーザーに見えるものと届くものを、ここに詳しく書きます。

- **`ps`。** `run` と mitmproxy のコマンドラインが見えます。そこには、デバイス名、`--allow-hosts` と `--pass-hosts` のホスト、ルールファイルと状態ディレクトリのパス、上流プロキシのアドレスが出ます。`--mask-names` や `--mask-values` を `@FILE` ではなくコマンドラインに書いたときは、それも出ます（コードから判断したものです）。SOCKS5 のパスワード、トークン、mitmweb のパスワードは出ません。これらは 0600 のファイルで渡すからです。
- **`--local-proxy`。** このポートはどのユーザーのリクエストも受け付け、許可したホストへのものを `local` として記録します（[セキュリティの詳細](#security-local-proxy)）。mitmproxy の SOCKS5 のポートと mitmweb のポートも 127.0.0.1 にありますが、パスワードで守られています（[下記](#security-other-processes)）。
- **ノードのポート。** これは、このコンピュータ自体があなたのユーザーとして tailnet に入っているときです。ノードが見分けるのはデバイスで、このコンピュータのユーザーではありません。そのため、ほかのユーザーのプログラムはあなた自身のデバイスの 1 つとして `--ui`、`--web`、`--mcp-http` に届きます。このコンピュータが `--device` に入っていれば、Exit Node と Remote Proxy にも届きます。最初の 3 つからほかのユーザーを締め出しているのは、トークンです（コードから判断したもので、2 人目のユーザーでは試していません）。
- **状態ディレクトリの外に書いたもの。** HAR ファイルのモードはシェルの設定に従うので、たいていほかのユーザーも読めます。`/tmp` は全員が使う場所です。`(umask 077; reqcove har > FILE)` とすれば、新しいファイルは 0600 になります（zsh で試しました）。サービスのファイル（LaunchAgent、systemd のユニット）は 0644 です。そこに入るのはパスで、トークンは入りません（コードから判断したものです）。

<a id="security-other-processes"></a>

### このコンピュータのほかのプロセス

mitmproxy のポートを守るパスワードと、対象外のものは、[SECURITY](SECURITY.ja.md#このコンピュータのほかのプロセス) にあります。ポートの持ち方は次のとおりです。

- Reqcove は `run` の間ずっとポートを持ち続けます。Reqcove は自分でポートを bind します。bind は `run` ごとに 1 回です。待ち受けているソケットは、起動する mitmdump のそれぞれに渡します。mitmproxy（12.3.1）にはそのためのオプションがないので、Reqcove のランチャー（`mitm.py`。別の `--mitmproxy-spec` でも使います）が、mitmproxy に自分で bind させず、渡したソケットで待ち受けさせます。mitmdump が落ちると、Reqcove はポートを持ったまま mitmdump を起動し直します（`ps` で見えます）。そのため、その合間にも、最初の mitmdump の前にも、ほかのプロセスがそのポートの 127.0.0.1 を取ることはできません。
- その間に来た接続はソケットのキューで次の mitmdump を待ちます。デバイスの接続は、アドオンが hello を送るまで待ちます（最長 15 秒で、それを過ぎると失敗します）。
- キューにある接続を、パスワードの確認が読み込まれる前に読むことはありません。mitmproxy は `proxyauth=any` で動き、パスワードを確かめるのは Reqcove のアドオンだけです。そこで、ランチャーは mitmproxy に、accept をしないままソケットの上にサーバーを作らせます。アドオンは読み込まれたとき、hello の直前に accept を始めます。
- **ランチャーの変更が当たらなかったとき**（mitmproxy が別の方法で bind するとき）は、mitmproxy 自身の bind が、Reqcove の持つポートで失敗します。mitmproxy は hello の前に終了し、準備完了にはなりません。
- 別のユーザーでは試していません。macOS と Linux のカーネルの文書によると（ここでは確かめていません）、2 つ目のソケットがそのアドレスを取れるのは、両方のソケットが SO_REUSEPORT を設定したときだけです（Linux では同じユーザーのときだけ）。Reqcove のソケットは SO_REUSEPORT を設定しません。

確認状況：macOS で本物の mitmproxy を使ったテストと、単体テスト（CI の Linux でも実行）で確かめました。

- uvx 経由だけで確かめたこと：mitmdump が落ちている間にキューに入った接続は、誤ったパスワードを一度に送っても 1 段ずつ送っても拒否され、何も中継も記録もされません。
- ロックからの起動と uvx 経由の両方で確かめたこと：mitmdump の再起動中はポートを bind できず、その間に送ったリクエストは次の mitmdump が記録します。
- 単体テストで確かめたこと：mitmdump が落ちている間と、Reqcove が再起動をあきらめたあとは、ポートを bind できません。Stop でポートが空きます。

macOS で同じユーザーとして、手で次のことを試しました。

- そのポートの 127.0.0.1 への bind は、SO_REUSEADDR と SO_REUSEPORT を付けても失敗します。0.0.0.0 への bind は SO_REUSEADDR で成功しますが、127.0.0.1 への接続はより具体的な Reqcove のソケットに届きます。
- ランチャーがすぐに accept し、アドオンの読み込みを 1.5 秒遅らせると、キューの接続のテストは失敗します。遅らせないときは、mitmproxy がたまたま先にアドオンを読み込みました。
- ランチャーの変更を遅すぎる時点で当てると、「address already in use」で終了します。

<a id="security-mitmproxy-code"></a>

### mitmproxy 自身のコード

ロック、ハッシュを確かめる場合、ロックが上書きしている 1 つのバージョンは、[SECURITY](SECURITY.ja.md#mitmproxy-自身のコード) にあります。そのほかの点は次のとおりです。

- ロックファイルは `internal/capture/mitm.py.lock` です。`run` はロックファイルと小さなランチャーを状態ディレクトリに書きます。
- `--uvx` のファイル名が `uvx` でないときは、ラッパーとして扱います。その `uv` が何かは分かりません。このときと、別の `--mitmproxy-spec` のときに使う素の `uvx` は、決まった日付より前のリリースを使います（`--exclude-newer`）。
- CI は、ロックがランチャーと合っていることも確かめます。
- `--uvx` のラッパーを通すときも、デフォルトの mitmproxy にはロックの上書きを当てます。tornado はロックの日付の時点のもの（6.6.1）になります。ハッシュは確かめません。
- 別の `--mitmproxy-spec` では上書きを当てず、その mitmproxy が求める tornado になります（コードから判断したものです）。mitmproxy 12.3.1 では 6.5.10 です。6.5.10 の脆弱性は mitmweb のサーバーにあり、`--web` がそのサーバーを動かします。

確認状況：試したこと（1 つのパッケージのハッシュを変えたロックは、キャッシュが空のときも、いっぱいのときも断られました。`uvx` はハッシュを与えても確かめませんでした。別の `--mitmproxy-spec` として指定した mitmproxy 12.3.1 では、tornado が 6.5.10 になりました）。2026-11-14 に uv 0.13.4 で試したこと：ラッパーを通すと、ほかのパッケージはロックのバージョンになり、`--web` のテストは通りました。Reqcove の `--web` のテストは tornado 6.6.1 で通ります。
