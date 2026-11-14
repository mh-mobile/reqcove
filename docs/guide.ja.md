# Reqcove ガイド

[English](guide.md) · [README](../README.ja.md)

README の 4 つの手順を終えたあとに読むガイドです。各節の最後に、試したことと試していないことを「確認状況」として書いています。

1. [セットアップする](#セットアップする)：[初回の起動](#初回の起動ログインと承認) · [停止・再起動・アップデート](#停止再起動アップデート) · [2 台で同じ CA](#2-台のコンピュータで同じ-ca-を使う) · [元に戻す](#元に戻すreqcove-cleanup)
2. [エージェントに通信を読ませる](#エージェントに通信を読ませる)：[ツールを許可する](#ツールを許可する) · [Skill](#使い方を教える-skill-を入れるreqcove-init) · [マーカー](#マーカーを置くreqcove-mark) · [ほかのデバイスのエージェント](#ほかのデバイスのエージェントから使う--mcp-http)
3. [自分でフローを見る](#自分でフローを見る)：[iPhone で](#iphone-で見る--ui) · [HAR ファイルで](#har-ファイルに書き出すreqcove-har) · [mitmweb で](#mitmweb-で見る--web)
4. [iPhone アプリ以外のクライアントを記録する](#iphone-アプリ以外のクライアントを記録する)：[証明書ピンニングをするアプリ](#証明書ピンニングをするアプリを通す--pass-hosts) · [gRPC](#grpc) · [Android](#android-を記録する) · [iOS シミュレーター](#ios-シミュレーターを記録する--local-proxy) · [Web アプリのバックエンド](#web-アプリのバックエンドを記録する) · [Wi-Fi のプロキシ](#exit-node-を使わずに-wi-fi-のプロキシでつなぐ) · [別の Mac](#別の-mac-を記録する)
5. [リクエストの行き先を変える](#リクエストの行き先を変える)：[ルール](#ルールを書く--rules) · [モック](#ここで応答するmock) · [プリセット](#エージェントが有効にできるプリセット) · [ルールが当たった理由](#ルールが当たった理由当たらなかった理由list_rulesexplain_rules) · [上流プロキシ](#上流プロキシに回す--upstream-proxy)
6. [Tailscale を使わずに同じネットワークでつなぐ（LAN モード）](#tailscale-を使わずに同じネットワークでつなぐ--lan)
7. [サービスとして動かす](#サービスとして動かす)：[`brew services`](#常駐させるbrew-services) · [`reqcove service install`](#homebrew-なしで常駐させるreqcove-service-install)
8. [コンテナで動かす](#コンテナで動かす)
9. [うまくいかないとき](#うまくいかないとき)
10. リファレンス：[オプション](#オプション) · [MCP ツール](#mcp-ツール) · [制限事項](#制限事項) · [セキュリティ](#セキュリティ) · [互換性](COMPATIBILITY.ja.md)

## セットアップする

インストールは [README](../README.ja.md#インストール) にあります。初回の 4 つの手順も README にあります（[使い方](../README.ja.md#使い方)）。

### 初回の起動：ログインと承認

`reqcove setup` をターミナルで実行すると、初回の手順を順に案内します。入力か出力がターミナルでなければ、エージェントからの実行などとして断ります。どの手順も空の答えで飛ばせます。何も起動せず、何も消しません。

- **uv**：`uvx` の場所を示すか、入れ方を表示します。入れはしません。
- **デバイスとホスト**：`--device` と `--allow-hosts` を引用符付きで、サービスが読むファイルに書きます。
  - ファイルは `~/.config/reqcove/config`（`reqcove service install` が読むもの）です。Homebrew で入れた場合（このバイナリが `Cellar/reqcove/` の下にあるとき）は、Homebrew の `$(brew --prefix)/etc/reqcove/config`（`brew services` が読むもの）です。
  - 0600 で、ディレクトリを新しく作るときは 0700 です。ファイルを置き換える前に、`run` と同じ読み方で確かめます。
  - `*` と、`-` で始まる名前は聞き直します。URL を貼り付けた場合はホストだけを書きます。
  - ホストがまだ決まっていなければ、`run` が動き始めてから `reqcove status`（またはエージェントの `summarize`）で iPhone がつないだホストを確認できます。
  - ファイルがすでにあれば表示し、`y` と答えない限りそのまま残します。`y` なら全体を置き換え、元のファイルは `config.old`（0600）として残します。`--rules` などほかのフラグは、そこから書き戻せます。
  - 普通のファイルでないものは触りません。
- **エージェント**：`y` と答えれば、`reqcove init` と同じように Skill を入れます。`claude mcp add reqcove -- reqcove mcp` を表示し、エージェントのコマンドは実行しません。`PATH` の `reqcove` がこのバイナリでない（ないか、別のもの）ときは、表示するコマンドでこのバイナリをフルパスで書きます（`service install` の表示も同じです）。
- **起動のしかた**：Homebrew で入れた場合は `brew services start reqcove`、それ以外は `reqcove service install`、またはターミナルで `reqcove run --config FILE` です。`--lan` はファイルに書けないので、ターミナルで `reqcove run --lan --allow-hosts HOSTS` を実行します。ログイン用の URL は表示しません（`reqcove links` が表示します）。
- **Ctrl-C** を押すと、その質問のところで止まります。それまでに書いたものは残ります。

残っている手順は `run` が表示し、`reqcove status` でも確認できます。

1. 表示された URL でログインします。
2. tailnet が Tailnet Lock を使っていれば、ノードに署名します。
3. Exit Node を承認します。

ログイン用の URL とリンクについては、次のとおりです。

- **表示される場所**：ログイン用の URL と、トークン付きの `--ui`、`--web`、`--mcp-http` のリンクは、`run` のターミナルにだけ表示されます。ログの行（`--verbose` のときも。ログイン用の URL は、`run` が知るまではよくある形で見分けます）と MCP のツールには出ません。ログイン用の URL を最初に開いた人の tailnet に、ノードが入ります（[SECURITY](SECURITY.ja.md#ログイン用の-url)）。
- **もう一度表示する**：自分のターミナルで `reqcove links` を実行します。QR コード付きで表示し、このコンピュータで開く mitmweb のリンクと CA のリンクも表示します。出力先がターミナルでなければ断ります（Claude Code の `!` からも表示されません。試しました）。
- **ターミナルでないところ**（サービス、`docker logs`）では、`run` はその代わりに「`reqcove links` prints it」と表示します。
- **`run` が動いている間**は、状態ディレクトリの `login-url` と `links`（0600）に置かれます。
- **承認を省く**：新しいノードのたびに Exit Node を承認する手間を省くには、tailnet のポリシーに自動承認を追加します：`"autoApprovers": {"exitNode": ["you@example.com"]}`

確認状況（`reqcove setup`）：単体テスト（答えを流し込み、一時的なホームディレクトリと Homebrew の prefix で実行）と、ターミナルで最初の質問のときに Ctrl-C を押すこと（すぐに終わり、何も書かれませんでした）と、macOS での実行（2026-11-14：uvx を見つけ、ファイルを書き（0600、ディレクトリは 0700）、Skill を入れ、コマンドを表示し、そのファイルで `service install` が動きました）。Ubuntu 24.04.5 LTS（arm64、tart の VM、ターミナル付きの ssh で、2026-11-14）でも試しました：`~/.local/bin` の uvx を見つけ、`~/.config/reqcove/config` を書き（0600、ディレクトリは 0700）、Skill はそのホームにエージェントが見つからないと表示し（実際にありませんでした）、`reqcove service install` を表示し、ターミナルでないときは断りました。試していないこと：setup が書いたファイルでの `brew services`。

### 停止・再起動・アップデート

- 停止：Ctrl-C で止めます。記録はメモリにあるので、一緒に消えます。そのあと iPhone の DNS が止まったままになったら（[tailscale#20870](https://github.com/tailscale/tailscale/issues/20870)）、Exit Node を一度オフにして、オンに戻してください。
- 再起動：`run` が止まっている間も `reqcove mcp` は動き続け、ツールは「動いていない」と答えます。`run` が戻れば、エージェントを再接続（Claude Code の `/mcp`）しなくても使えます。記録は空から始まり、最初の答えが `note` でそう伝えます。
- アップデート（`brew upgrade reqcove` や、ソースからのビルドで新しいバージョンを入れたとき）：新しい reqcove で `run` を起動し直し、エージェントを一度再接続します（新しいツールを使うためです。バージョンが違う間は、ツールがそう伝えます）。Skill も新しくするため、`reqcove init` をもう一度実行します。

確認状況：Claude Code のセッション中に `run` を再起動して確認しました。

### 2 台のコンピュータで同じ CA を使う

状態ディレクトリが同じであれば、CA も同じままです。`~/.reqcove/mitmproxy/` をディレクトリごと（秘密鍵が含まれます）、もう 1 台の `~/.reqcove/` にコピーします。コピー先の reqcove は止めておくか、初めて起動する前にコピーしてください。

### 元に戻す（`reqcove cleanup`）

`reqcove cleanup` が手順を表示します。`--delete-state` を付けると、状態ディレクトリを削除します。先に次のことをしてください。

- iPhone から CA のプロファイルを削除します（[SECURITY](SECURITY.ja.md#ca-の秘密鍵)）。
- サービスを止めます（`brew services stop reqcove` か `reqcove service uninstall`）。止めないと、サービスは次のログインで `run` をまた起動し、状態ディレクトリを作り直します。

## エージェントに通信を読ませる

`claude mcp add reqcove -- reqcove mcp`（README の手順 4）を実行すると、このコンピュータのエージェントが [MCP ツール](#mcp-ツール)を使えるようになります。Codex なら `codex mcp add reqcove -- reqcove mcp` です。`run` が両方を表示します。

ツールにできることは次のとおりです。

- **読む**：シークレットは届いた時点でマスクされます（[マスクで見つけられないもの](SECURITY.ja.md#記録するもの)）。
- **プリセットを有効にする**：ツールにできる変更はこれだけです。[プリセット](#エージェントが有効にできるプリセット)は、あなたがプリセットにしたルールです。モックか、v0.7 からはリクエストの中身や行き先を変える `map_remote`、`modify_headers`、`resolve` のルールです。有効になるのは 1 回につき最長 5 分で、何度でも有効にし直せます。プリセットがなければ、ツールは読むだけです。`--mcp-http` からは有効にできません。
- **[マーカー](#マーカーを置くreqcove-mark)を置く**：デバイスには何も変えません。

### ツールを許可する

- 読むツールには読み取り専用の印（`readOnlyHint`）を付けています。クライアントが確認を減らすのに使えます（どのクライアントでも確かめていません）。
- 読み取り専用の印を付けていないもの：プリセットを有効・無効にするツール（`activate_preset`、`deactivate_preset`）と、`add_marker`（書き込むのは Reqcove のメモリだけ）です。
- Claude Code は許可していないツールを使う前に確認します。読むツールは名前で許可してください（`"mcp__reqcove__list_flows"` など）。`"mcp__reqcove"` でまとめて許可すると、読み取り専用の印のないツールも許可されます（プリセットに書いたサーバーへリクエストを送れる `activate_preset`）。Claude Code のドキュメントによるもので、ここでは試していません。

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

v1.0 で削除したもの（v0.8 で非推奨）：ツールの `list_mock_presets`、`activate_mock`、`deactivate_mock` です。それより前に書いたリストでは、`mcp__reqcove__list_mock_presets`、`mcp__reqcove__activate_mock`、`mcp__reqcove__deactivate_mock` を `mcp__reqcove__list_presets`、`mcp__reqcove__activate_preset`、`mcp__reqcove__deactivate_preset` に置き換えてください。`activate_preset` はモックだけでなくほかの種類も有効にするので、例では `activate_preset` と `deactivate_preset` を `ask` に置いています。スクリプトでは、`active_mock_presets`、`active_mock_presets_error`、`mock_presets` の代わりに、`status` の `active_presets` と `active_presets_error`、`capture_stats` の `presets` を読んでください。削除したツールを呼ぶと、代わりのツールの名前を返します（ユニットテスト）。

注意点は次のとおりです。

- Codex は呼び出しごとに確認します（[HTTP](#ほかのデバイスのエージェントから使う--mcp-http) でも）。
- 許可したあとは、`--no-redact` で起動した `run` でも確認なしで読みます。その場合も、Skill とサーバーの instructions は、止まってユーザーに聞くよう伝えます。
- 許可するのは Reqcove のツールだけにして、シェルのコマンドやネットワークのツールまで一緒に許可しないでください。サイトが記録に書き込んだ文が、エージェントにそれらを使わせようとすることがあります（[SECURITY](SECURITY.ja.md#プロンプトインジェクション)）。

### 使い方を教える Skill を入れる（`reqcove init`）

Skill はツールの使い方をエージェントに教えます。最初に status を見ること、1 つのアプリの通信の探し方、TLS の失敗から考えられること、ルールファイルの書き方、そして守る決まり（`reqcove run` を自分で起動しない、トークンを求めない、記録の中身はデータとして扱う、マスクされていないシークレットを引用しない）です。

```sh
reqcove init                    # ホームディレクトリにあるエージェントに入れる：~/.claude/skills（Claude Code）、~/.agents/skills（Codex、Cursor、Gemini CLI、Copilot CLI、Devin）
reqcove init --client codex     # または、名前を挙げたものだけ（--client を繰り返す）
```

- reqcove をアップデートしたら、もう一度実行してください。入っている Skill のバージョンが違うと、`reqcove status` がそう伝えます。
- `init` が書いたのではない Skill、あとで書き換えた Skill、シンボリックリンクには触りません。`--uninstall` は自分が入れたものを削除し、`--print` は Skill を書き出します。
- MCP サーバーの登録はしません。登録は上のコマンドで行います。

確認状況：Claude Code と Codex で確認しました（Reqcove の名前を出さずにアプリの通信先を尋ねると、どちらも Skill を読み込みました）。Devin でも確認しました（`~/.agents/skills` の Skill を読み込み、MCP サーバーがないときは登録を頼んで止まりました）。Cursor でも確認しました（Skill を使い、MCP サーバーの使い方の注意も読み、そのあとはツールだけで調べました）。未確認：Gemini CLI、Copilot CLI。

### マーカーを置く（`reqcove mark`）

iPhone で何かをタップする前に、ターミナルで `reqcove mark "tap Pay"` とすると、記録の中にマーカーを置けます。エージェントは `list_markers` で読みます（古い順、`since` で絞れます）。エージェントは、操作する前や、あなたが「いまから X をタップする」と言ったときに、`add_marker` で自分のマーカーを置きます。`add_marker` は `id`、`time`（`list_flows` などの `since` と、報告に使う）、`checkpoint`（`wait_for_flows` の `after` に使う）を返します。

- テキストは 1 行で 80 文字まで。長いものや、改行などの制御文字を含むものは、切り詰めずに断ります。エラーの文と同じくマスクします（トークンは `[redacted]` になります）。
- `source` は `cli`（`reqcove mark`）か `mcp`（`reqcove mcp` を通したエージェント）です。経路を示すだけで、誰が置いたかの証拠ではありません。このコンピュータでコマンドを実行できるエージェントは、`cli` を名乗れます。`reqcove mark` を実行する（`reqcove lan` と同じく、断るのは入力か出力がターミナルでないときだけです）か、`run` のソケットに自分でつなぐかです。
- 置いた経路ごとに 100 個まで残し、古いものから消します。メモリにだけ置くので、フローの id と同じく、`run` を再起動すると消えます。`reqcove mcp` を通したエージェントは `mcp` になり、あなたのマーカーを押し出せません。上のように `cli` を名乗るエージェントは押し出せます。`--mcp-http` からは使えません。
- `add_marker` は書き込みのツールです（読み取り専用の印はありません）が、デバイスには何も変えません。`reqcove mcp` は、接続が切れたあとに送り直しません。

確認状況：iPhone を使った確認の中で、Claude Code から `add_marker` を使いました（iOS 27.3、2026-11-14：動きました）。ほかはテストのみです（`reqcove mark` は手で試していません）。

### ほかのデバイスのエージェントから使う（`--mcp-http`）

tailnet のほかの場所にいるエージェント、たとえば Grok Bot（xAI のエージェント。クラウドのコンピュータが、Tailscale の OAuth apps で tailnet に入ります）から使うには、次のように起動します。

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' --mcp-http
```

`run` は、次のものを除いた同じツールを、ノードから HTTP で提供します。

- プリセットのツール：`list_presets`、`activate_preset`、`deactivate_preset`
- ルールのツール：`list_rules`、`explain_rules`
- マーカーのツール：`add_marker`、`list_markers`

URL（`http://reqcove.<tailnet>.ts.net:8090/mcp`）と、エージェントに渡すヘッダー（`Authorization: Bearer <トークン>`）も表示します。`reqcove links` でもう一度表示できます。ターミナルでないときは、`reqcove links` だけが表示します。

- **Grok Bot**：
  1. 「Connect apps › Tailscale」で tailnet に入れます。Tailnet Lock を使っていれば、そのデバイスに署名します。
  2. 「Connect apps › カスタムコネクタを追加」を開きます。種類は「リモート HTTPS」です（名前は HTTPS ですが、tailnet の `http://` の URL で使えます。tailnet の中は WireGuard で暗号化されています）。サーバー URL にその URL、HTTP ヘッダーにキー `Authorization` と値 `Bearer <トークン>` を入れます。ヘッダーの値は画面に出さずにコピーできます：`printf 'Bearer %s' "$(cat ~/.reqcove/mcp-token)" | pbcopy`
  3. チャットで頼んでください。設定画面では、このコネクタは「エラー」でツール 0 個と表示されます。Grok Bot が tailnet に届くのはチャットの中だけだからです。
- **ほかのコンピュータの Claude Code**（ヘッダーは `~/.claude.json` に保存されます）：
  `claude mcp add --transport http reqcove-remote http://reqcove.<tailnet>.ts.net:8090/mcp --header "Authorization: Bearer <トークン>"`
- **ほかのコンピュータの Codex**（トークンはその環境変数に入れます）：
  `codex mcp add reqcove-remote --url http://reqcove.<tailnet>.ts.net:8090/mcp --bearer-token-env-var REQCOVE_TOKEN`。
  Codex は MCP ツールを呼ぶたびに承認を求めます。承認を求められない `codex exec` では、このサーバーに `default_tools_approval_mode = "approve"` を設定します。

注意点は次のとおりです。

- 呼べるのは、tailnet にある自分のデバイス（タグなし）で、トークンを持つものだけです（[SECURITY](SECURITY.ja.md#http-経由の-mcp--mcp-http)）。タグ付きのデバイスは拒否します（`run` が一度ログに出します）。エージェントのデバイスを制限する目的で、タグを付けないでください。
- エージェントが読んだものは、そのエージェントのコンピュータと、モデルの提供元に渡ります（Grok Bot なら xAI のクラウド）。エージェントを止めるには、状態ディレクトリの `mcp-token` を削除して `run` を再起動するか（削除しない限り、トークンは起動のたびに同じです）、そのデバイスを tailnet から外します。
- `run` を再起動しても、再接続は要りません（止まっている間の呼び出しは失敗します）。記録は空から始まり、再起動前のカーソルは拒否します。
- `run` は、呼び出しごとにデバイスとツール名をログに出します（`--mcp-http: grokbot-user-1 (100.104.0.1) called "list_flows"`。引数は出しません）。トークンがない、または違うリクエストもログに出します。「確認します」と言うだけで呼んでいないエージェントは、ログに行が出ません。
- 1 台のデバイスから呼べるのは、1 秒におよそ 10 回までです。超えると、しばらく `429` が返ります（`run` は 1 分に 1 回ログに出します）。
- 通信は HTTP のままですが、tailnet の暗号化（WireGuard）の中を通ります。コンテナでも同じフラグで動き、ポートの公開は不要で、トークンは `docker exec -it 名前 reqcove links` で表示できます（[コンテナ](container.ja.md#3-エージェント)）。

確認状況：Grok Bot で確認しました（status、フロー、ボディの取得。`run` の再起動後も同じチャットで継続。コンテナの `run`）。この Mac の Claude Code（`claude -p`）と Codex（`codex exec`）からも、tailnet 越しに確認しました（どちらも status を取得）。ほかのコンピュータ（tailnet にいる macOS の VM）からも、ノードの名前と IP の両方で呼べることを確認しました。

## 自分でフローを見る

### iPhone で見る（`--ui`）

通信を送っているアプリの横で、フローを見たいときに使います。

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' --ui
```

`run` は、ノードの 80 番ポートで読み取り専用のページを提供し、そのリンクを QR コードと一緒に表示します（`reqcove links` でもう一度表示できます。ターミナルでないときは `reqcove links` だけが表示します）。iPhone のカメラで読み取ると、Safari で一覧が開きます。一覧は 1 秒ごとに新しいフローを追います（Split View でアプリと並べることもできます）。フローをタップすると、ヘッダーとボディを確認できます。MCP ツールが返すものと同じく、マスク済みです。

- 検索欄に入力すると、その場で URL とヘッダーを絞り込みます。「bodies too」をオンにすると、保持しているボディの先頭も対象になり、一覧は新しいフローを追わなくなります（すべての記録を調べるためです）。ステータス（2xx〜5xx、応答なし）や、フローのページからホストでも絞り込めます。
- Clear はそれまでのフローを一覧から隠します。「Show all」で戻ります。削除はしないので、エージェントからは引き続き見えます。
- Live / Paused で、新しいフローを追うかどうかを切り替えます。下にスクロールしている間は一覧を動かさず、新しいフローの件数を表示します。件数をタップすると表示されます。
- tailnet にある自分のデバイスからは、すべてのデバイスのフローが見えます。`--device` に指定した他人のデバイスからは、そのデバイス自身のフローだけが見えます（[それ以外のデバイスと、トークンの扱い](SECURITY.ja.md#ページ--ui)）。
- リンクは起動のたびに同じなので、再起動後もブックマークから開けるはずです。リンクを変えるには、状態ディレクトリの `ui-token` を削除して起動し直します。
- Tailscale はオンにしておく必要があります。Exit Node や [Remote Proxy](#exit-node-を使わずに-wi-fi-のプロキシでつなぐ) は使っていなくてもかまいません。このページ自身の通信は記録されません。

確認状況：iPhone で確認しました（カメラから開く、新しいフローを追う、検索、Clear と Show all、`run` の再起動後に Safari で開き直す）。

### HAR ファイルに書き出す（`reqcove har`）

`reqcove run` が動いている間に実行します。

```sh
reqcove har > flows.har
```

フローを HAR 1.2 のファイルに、古い順で書き出します。デフォルトは新しい 1000 件です（`--limit 0` ですべて）。`--host`、`--device`、`--since 10m`、`--until`、`--status 4xx`、`--method`、`--user-agent` で絞り込めます。

- 中身は MCP ツールが返すものと同じです。届いた時点でマスク済みで、ボディは先頭だけです（切り詰めたボディは、コメントにその旨が入ります）。マスクで確認できなかったボディは含まれません。`run --no-redact` のときは何もマスクされず、ファイルのコメントにその旨が入ります。
- ファイルのパーミッションはシェルの設定に従うので、ほかのユーザーから読めることがあります（[SECURITY](SECURITY.ja.md#記録するもの)）。

確認状況：Chrome の開発者ツール（Network）に読み込めることを確認しました（リクエスト、マスクされたヘッダー、レスポンスが見えます）。未確認：Charles、Proxyman で開くこと。仕様から：HAR 1.2 の必須項目を出力します（検証ツールは実行していません）。

### mitmweb で見る（`--web`）

リクエストの編集やリプレイができる、mitmproxy 自身の画面を使いたいときに使います。

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' --web
```

mitmdump の代わりに mitmweb が起動します。このコンピュータでは `http://127.0.0.1:8081`（ほかの run が 8081 を使っていれば 8091〜8099。[アドレスは 2 つ](several-exit-nodes.ja.md#ポート)）、tailnet にある自分のデバイスからはノードの 8081 番ポートで、`run`（または `reqcove links`）が表示するリンクか QR コードから開けます。

- 何もマスクされません（[SECURITY](SECURITY.ja.md#mitmweb--web)）。ボディは 1 つ 2 MB まで表示し、新しい 1 万件のフローと、合計 256 MB までのボディを保持します。この上限が数えるのは、終わったフローだけです。まだ続いているフロー（届き続けるダウンロードやイベントストリーム、応答を待っているリクエスト）は終わったときに数えます。それまで Reqcove が mitmweb のために保持するボディ（向きごとに 2 MB まで）は、この上限の外です（コードを読んだもので、測っていません）。
- リンクは起動のたびに同じです（トークンは状態ディレクトリの `web-token`）。再起動後はリンクをもう一度開いてください。トークンなしのブックマークでは、トークンの入力を求められます。
- Capture タブの「Run SOCKS Proxy」は、オンのままにしてください。オフにすると、デバイスの HTTP(S) が止まります。そこにあるほかのモードは、Reqcove では使いません。変更した設定は、reqcove を再起動すると元に戻ります。

確認状況：Exit Node を使っている iPhone から確認しました。コードから（未確認）：mitmweb で設定を変えても、Reqcove の記録の範囲とマスクは変わりません。

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

証明書ピンニングをするアプリは Reqcove の証明書を拒否するので、そのホストへのリクエストは失敗します。`reqcove status` が、該当するホストと、`run` に付ける `--pass-hosts` を表示します。付けて起動すると、そのホストは復号せずに通り、アプリが動きます。

```sh
reqcove run --device iphone --allow-hosts '*' --pass-hosts '*.example-cdn.com,api.example.com'
reqcove run --device iphone --allow-hosts '*' --pass-hosts @pass-hosts.txt   # 1 行に 1 ホスト
```

- そのホストは接続だけを記録します（ホスト、接続先サーバー、時刻、バイト数：`list_passthrough`）。URL や中身は記録しません。
- その接続は `--rules` と `--upstream-proxy` の対象外です。ただし mitmproxy がそれでも復号するリクエスト（平文の HTTP や、許可したホストの接続に相乗りしたもの）は、記録されず `--rules` も効きませんが、`--upstream-proxy` は通ります。
- TLS ハンドシェイクのあとで行うピンニングは、どこにも表示されません。
- 自分のアプリなら、ピンニングを外したビルドを使ってください。Android のアプリが CA を拒否するのは、別の理由です（[Android](#android-を記録する)）。

確認状況：iPhone で確認しました。pass host の復号されたリクエストが `--upstream-proxy` を通ることはテストで、`--rules` が効かないことはコードを読んで確認しました。

### gRPC

gRPC の呼び出しは 1 件のフローになります。パスがメソッド名（`/pkg.Service/Method`）です。

- **ステータス**：一覧の行と `summarize` に `grpc_status` が出ます（`0` が成功、`16` が UNAUTHENTICATED など。トレーラーが届くまでは `pending`）。メッセージのない答え（trailers-only。エラーのときの普通の形）ではレスポンスのヘッダーから、それ以外はトレーラーから読みます。トレーラーは HTTP/2 のもので、gRPC-Web では最後のフレームです（残したボディの先頭に入っているときだけで、64 KiB を超えるボディでは読めません）。
- **`grpc_message`** はデコードしてマスクします（`--no-redact` のときは送られたまま）。
- **トレーラー**は検索の対象になり、`diff_flows` で比べられ、HAR ではコメントに入ります。
- **メッセージ**：ボディの注記には、メッセージの数と大きさが出ます。JSON のメッセージ（`application/grpc+json`、`connect+json`）は 1 行に 1 つずつ、JSON としてマスクして返します。protobuf のメッセージは下のとおりです。
- **Connect のストリーム**：最後のフレーム（エラーとトレーラー。JSON）は、`[end of stream]` として JSON と同じくマスクして返します。ストリームの結果はこのフレームにあり、`grpc_status` には出ません（テストだけで確かめました）。
- `-bin` で終わる**メタデータ**（バイナリ）は、大きさだけを出します。

protobuf のボディ（gRPC のメッセージや、`application/x-protobuf` など）はテキストではないので、Reqcove は中身のバイト列ではなく、Reqcove が書き起こしたものを返します。ボディの `view` がその印です。スキーマがないときは構造だけです。

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

gRPC-core の上に作ったアプリ（Google の SDK など）は、iPhone が信頼する CA ではなく、自前の CA の一覧を使うので、呼び出しは TLS の失敗として出ます（gRPC のメーリングリストによるもので、試していません）。gRPC のライブラリに信頼する証明書を指定するアプリも同じです。デバッグ版で Reqcove の CA を信頼させれば別です（試していません）。

確認状況：確かめたのは 2 つです。1 つは iPhone の試験用アプリで、URLSession（システムの信頼。CA を入れた状態）から Connect のデモサーバーを Connect、gRPC-Web、gRPC で呼び、`--proto` も付けました（ステータスはトレーラーと gRPC-Web の最後のフレームから、メッセージは名前付きで。ただし gRPC のレスポンスは、試したビルドでは出ませんでした。そのあと直し、テストで確かめましたが、iPhone では試し直していません。スキーマなしの表示はテストだけです）。もう 1 つは E2E テストで、mitmproxy を通した HTTP/2 上の gRPC の形（トレーラーにステータスが入る 64 KiB を超えるボディと、trailers-only のエラー）です。

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

- macOS：Charles や Proxyman と同じように、`run` がシステムの Web プロキシ（HTTP と HTTPS、有効なネットワークサービスすべて）をこのプロキシに向け、止まるとき（Ctrl-C、`kill`、ターミナルを閉じたとき）に元の設定へ戻します。起動中のシミュレーターには Reqcove の CA も追加します（`xcrun simctl keychain … add-root-cert`）。あとから起動したシミュレーターには、表示されるコマンドで追加してください。
- Linux：設定は何も変更しません。アプリをプロキシに向け（`HTTPS_PROXY=http://127.0.0.1:8082`）、CA を信頼させてください。
- シミュレーターだけでなく、このコンピュータのすべてのアプリの通信がこのプロキシを通ります。復号して記録するのは `--allow-hosts` のホストだけですが、そのホストは、Reqcove の CA を信頼していないアプリ（Mac の Safari など）ではつながらなくなります。
- `kill -9` や異常終了のあとは、次の `run` か `reqcove cleanup` がプロキシの設定を戻すまで（またはシステム設定で自分で戻すまで）、システムのプロキシを使うアプリがつながりません。
- このコンピュータ、LAN、tailnet（IPv4 と IPv6、`*.ts.net` も）、`*.local` はプロキシの例外に入れるので、これまでどおり直接つながります。名前解決はこのコンピュータと同じ方法で行い（VPN、split DNS、検索ドメインも有効）、`--dns` は使いません。このコンピュータ自身やリンクローカルアドレスに解決される名前は、`/etc/hosts` にあるものを除いて拒否します（[SECURITY](SECURITY.ja.md#ローカルプロキシ--local-proxy)）。
- 自動プロキシ構成（PAC）と認証付きプロキシの設定は、変更しません。

このコンピュータのブラウザも、警告で止めるのではなく記録したいときは（`local` として、シミュレーターの通信と一緒に記録されます）、このコンピュータに Reqcove の CA を一度信頼させます。コマンドは `run` が表示し、やめ方は `reqcove status` と `reqcove cleanup` が表示します。信頼させると、CA の秘密鍵を持つ人は、このコンピュータに対しても任意の HTTPS サイトになりすませます（[SECURITY](SECURITY.ja.md#ローカルプロキシ--local-proxy)）。

- macOS（TLS だけを信頼。パスワードを求められます）：`security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem`。Firefox は独自の証明書ストアを使うことがあります。やめるには、`reqcove status` が表示するコマンドを実行するか、キーチェーンアクセスで CA を削除します（信頼の設定も一緒に消えます）。
- Debian と Ubuntu：`sudo cp ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/reqcove.crt && sudo update-ca-certificates`。Fedora：`/etc/pki/ca-trust/source/anchors/` に置いて `sudo update-ca-trust`。
- Linux の Chrome と Chromium：`certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n Reqcove -i ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem`。Node：`NODE_EXTRA_CA_CERTS=` にそのファイルを指定します。Python：更新後のシステムの CA バンドルを指定します（そのファイルだけを指定すると、ほかの CA がすべて使えなくなります）。

確認状況：macOS 27 で確認しました（信頼させるコマンドと Reqcove による信頼の確認、やめ方の表示、キーチェーンアクセスでの削除、Mac の Chrome で許可したホストが警告なしに開けて記録されること、本物の `networksetup` でシステムの Web プロキシが 127.0.0.1:8082 に向き、Ctrl-C で元に戻ること、起動中のシミュレーターに CA が入ること、iOS 27 のシミュレーターの Safari の通信が `local` として復号・記録されること）。`networksetup` は tailnet の IPv6 の範囲（`fd7a:115c:a1e0::/48`）を例外として受け付け、システムの設定にも入りました（2026-11-13 に試しました）。RoamRun と一緒に使うこと（2026-11-14 に RoamRun 0.12.0 とその PR #253 で試しました）：`--local-proxy` を有効にしたまま、`roamrun doctor` は問題なしで、`roamrun up` は別の Wi-Fi にいる iPhone を tailnet 越しにブリッジし、Ready になりました（`--local-proxy` なしのときと同じ）。未確認：プロキシの例外のアドレスの書き方をアプリが守るか、PAC や認証付きプロキシのある環境、Linux。

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

確認状況：この Mac をデバイスにして、Rails 8 のアプリから Net::HTTP と Faraday で API を呼んで確認しました（CA がないと Ruby が証明書を拒否して TLS の失敗が記録され、CA があると両方の呼び出しが記録されました）。未確認：ほかのクライアント、別のマシンのサーバー。

### Exit Node を使わずに Wi-Fi のプロキシでつなぐ

ノードは **Remote Proxy** も提供しています。ノードの tailnet アドレスのポート 8080（`--proxy-port`）で動く HTTP プロキシで、`--device` のデバイスが使えます。iPhone では、Exit Node を選ぶ代わりに、Wi-Fi のプロキシ設定（手動）にこれを指定できます。モバイル通信にはプロキシ設定がないので、Wi-Fi でのみ使えます。

| | Exit Node | Wi-Fi のプロキシ |
|---|---|---|
| このコンピュータを通る通信 | iPhone のすべての通信（DNS、HTTP(S)、ほかのポート） | プロキシ設定に従うアプリの HTTP(S) |
| それ以外 | なし | iPhone の Wi-Fi から直接インターネットへ（記録なし） |
| モバイル通信 | 利用可 | 利用不可 |
| Tailscale アプリ | Exit Node を選択 | 接続したままにするだけ |

プロキシを通った通信は、Exit Node のときと同じく、このコンピュータからインターネットに出ます。名前解決もこのコンピュータで行います。

確認状況：iPhone で確認しました（Safari の通信が記録され、`--allow-hosts` にないサイトもこれまでどおり開けました）。

### 別の Mac を記録する

`--device` に指定した Mac で、Tailscale のアプリから Exit Node を選ぶと、iPhone と同じように記録されます（[手順](another-mac.ja.md)）。Homebrew のオープンソース版の `tailscaled` では、Exit Node は選ばれた表示になりますが、その Mac の通信は通りません。

確認状況：macOS 27 の VM で確認しました。未確認：その Mac の iOS シミュレーター（シミュレーターが Reqcove の CA を信頼していれば、Mac の通信と一緒に通るはずです）。

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
- 他人が作ったルールファイルは、中身を読んでから使ってください。ルールはアプリのリクエストを Cookie やトークンごと、書かれた先へ送れます。

確認状況：E2E テスト（本物の mitmproxy）で確認しました。確認したのは、POST のボディ、終わっていない POST、SSE への `map_remote`（どちらも流れるままに相手に届くこと）と `keep_host_header`、GET と POST に応答する `map_local` と、2 MiB のボディは本来の宛先へ送ること、両方向の `modify_headers`、`--allow-hosts` の外のリクエストには触れないこと、ルールの値が記録に入らないこと、読み込みで断るものです。これらのテストにないもの：長さのない HTTP/2 の GET への `map_local`、mitmproxy のメモリが尽きるほど大きなボディ。

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
- 拒否するもの：`0.0.0.0/8`、リンクローカル（クラウドのメタデータ）、マルチキャスト、Tailscale の 100.100.100.100（[SECURITY](SECURITY.ja.md#ルール--rules)）。`--upstream-proxy` と一緒に使う `resolve` も拒否します。

確認状況：E2E テスト（本物の mitmproxy）で確認しました。確認したのは、平文の HTTP がアプリの `Host` のままルールのアドレスへ送られ、送り先が記録に残ること、`map_remote` のあとの `resolve`、TLS で接続先にその名前（SNI）を求め、信頼できない証明書なら 502 になること、読み込みで断るもの（クラウドのメタデータ、100.100.100.100、名前の接続先、アドレスの共有、`--allow-hosts` にないホスト、`--upstream-proxy` との組み合わせ）です。別の名前の信頼された証明書を持つサーバーで 502 になることも試しました（[SECURITY](SECURITY.ja.md#ルール--rules)）。`resolve` のプリセットは iPhone では試していません（[下](#map_remotemodify_headersresolve-のプリセット)）。

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

- **`url`** は、アプリが送った URL のクエリを除いた部分と完全に一致したときに当たります（ホストの大文字と小文字は区別しません）。パスのあとの `*` で終わる `url`（`https://api.example.com/v1/*`）は、それより前の部分で始まる URL すべてに当たります。クエリ、フラグメント、ユーザー名、デフォルトのポートは書けません（決して当たらないので、読み込みで拒否します）。ホストは `--allow-hosts` に入っていて、`--pass-hosts` に入っていない必要があります。
- **`method`** と **`operation`** は省略できます。`operation` は GraphQL の operation です（`operationName`、Apollo の `X-APOLLO-OPERATION-NAME` ヘッダー、または文書の最初の名前付き operation）。
- **応答**：`status` は 100〜599 で、省略すると 200 です。ボディは書くかファイルで指定し、1 MiB までです。`HEAD`、204、304 にはボディを付けません。`Cache-Control` を書かなければ `no-store` を付けます。
- **`modify_headers` との関係**：リクエストに対する `modify_headers` のルールは一致を調べる前に効き、応答に対するものはモックにも効きます。
- **保持するもの**：モックが応答するかもしれないリクエスト（メソッドと URL が一致するもの）は、ボディが届くまで全体を保持します。長さが 1 MiB を超えるものや、長さの分からない POST は、モックせずに本来の宛先へ送り、`rewrites` に `mock: skipped, …` と残します。`map_local` と同じく、長さのない GET（HEAD、OPTIONS、DELETE も）も保持し、HTTP/2 で一緒に送られてきたボディは、すべてメモリに保持します。
- **記録**にその旨が残ります。一覧の行に `mocked: true`、`rewrites` にルールの番号とステータス（`mock[0]: 401`）、HAR には注記が入ります。`capture_stats` の `rules_loaded` は、ファイルを最後に読み込んだ時刻です。

確認状況：E2E テスト（本物の mitmproxy）で確認しました。確認したのは、POST に対するヘッダー付きの 401、ボディの GraphQL operation による一致、`*` で終わる URL、HEAD、サーバーに届かないこと、拒否するルール（範囲外のステータス、ヘッダーの改行、ないファイル、`--allow-hosts` にないホスト）です。iPhone では、Safari（httpbin.org）への 401 と、GitHub アプリの GraphQL の operation 1 つをモックできることを確認しました（同じ接続のほかの operation は GitHub に届きました）。

#### ファイルを読み込むタイミング（`--rules-reload`）

ファイルは mitmproxy の起動時に読み込みます（`run` の起動時と、reqcove が mitmproxy を再起動するとき）。

`--rules-reload` を付けると、変更が落ち着いた時点で読み直します。新しいルールは、そのあとに始まるリクエストから適用します。処理中のリクエストは始まったときのルールのままです。

- 読み込めないファイルのときは前のルールのまま動き、`run` と `reqcove status` が理由を表示します。ただし、その間に mitmproxy が再起動すると、起動時と同じく `run` が止まります。
- ファイルに書き込めるもの（エージェントを含む）が、再起動なしで、デバイスのリクエストの行き先を変えられるようになります。

コードから：変更は 2 秒ほどで読み直されます。

#### ターミナルからモックを足す（`reqcove mock add`）

`reqcove mock add` は、モックを確かめてからファイルに書き足します。

```sh
reqcove mock add --rules rules.yaml --url https://api.example.com/v1/login \
  --method POST --status 401 --header 'Content-Type: application/json' \
  --body '{"error":"expired"}'
```

- **ほかのフラグ**：`--operation NAME`、`--body-file PATH`（入力した場所が基準で、フルパスで書きます）、`--delay-ms N`、`--fault close`、`--preset NAME`、`--description TEXT` です。
- **書く場所**：モックは `mock:` の最後の項目として足し、ファイルのほかの部分（コメントや順序も）はそのまま残します。`mock:` がなければ、ファイルの最後に足します。新しいファイルは `0600` で作ります。既にあるファイルはモードを保ったまま、一度に置き換えます（隣に一時ファイルを書き、名前を変えます）。
- **断るもの**：`mock:` がファイルの最後のブロックでないときや、フロー形式（`mock: []`）のときは断り、直し方を表示します。同じ名前のヘッダーを 2 回指定したときも断ります。確かめている間にファイルが変わったとき（エディタで保存したときなど）は何も書かないので、もう一度実行してください。
- **確認**：書く前に、書いたあとのファイル全体を、アドオン自身の読み込み処理で確かめます。`reqcove run` が動いていれば（同じ `--state`）、その `--allow-hosts` と `--pass-hosts` も使って run が確かめます。動いていなければ、ロックファイルの mitmproxy の Python（`--uvx PATH`）で確かめ、このときホストは確かめません。断ったときは理由を表示し（ルールの中身は出しません）、何も書きません。
- **効くタイミング**：書いたあと、モックがいつ効くかを表示します。run に `--rules-reload` があればすぐに効き、そのとき有効なプリセットはすべて無効になります。なければ run を起動し直したときです。
- **ターミナルでだけ動きます**（`reqcove mark` と同じく、標準入力と標準出力の両方）。頼まれていないエージェントが実行するのを防ぐ助けで、保証ではありません（シェルを使えるエージェントはターミナルを用意でき、どのみちファイルも書き換えられます）。`--print` は、書き込みも確認もせずにモックを YAML で表示します。ターミナルでなくても動きます。

確認状況：テストで確認しました。確認したのは、引用符、改行、`#`、`: `、制御文字、ほかの文字体系を含む値の YAML をアドオンの読み込み処理が元のとおりに読むこと、ファイルの中身が残ること（コメント、CRLF、末尾に改行のないファイル）、断る場合、本物の run による確認（範囲内と範囲外のホスト、`--pass-hosts` のホスト）と mitmproxy の Python による確認です。動いている run とデバイスでの手作業の確認はしていません。

#### エージェントが有効にできるプリセット

`preset: 名前` を付けたモックは、エージェントが有効にするまで何もしません。有効にできるのは 1 回につき最長 5 分で、何度でも有効にし直せます（上限なし。[SECURITY](SECURITY.ja.md#モックのプリセット)）。プリセットと同じ match（メソッド、URL、operation）の普通のモックは、読み込みで断ります（プリセットの代わりに応答してしまうためです）。エージェントが、ファイルを書き換えずに、503 や遅い応答、切れた接続をアプリがどう扱うかを確かめ、また無効に戻せます。

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
- 有効なプリセットは、ほかのモックより先に応答します。無効なプリセットは、モックとして扱いません。同じ match（メソッド、URL、operation）で有効にできるプリセットは 1 つです。同じ match の別のプリセットを有効にすると、先のものは無効になります。有効なものをもう一度有効にすると、期限と回数が置き換わります。
- 一致したリクエストは、誰が送ったものでも（Safari、別のデバイス、アプリの再試行）回数を使います。一覧の行には `preset: 名前` が付き、閉じたものの error には、モックが閉じたと書かれます。
- `delay_ms` と `fault: close` は、普通のモックでも使えます。`delay_ms` が遅らせるのはモックの応答だけです（サーバーからの応答は遅らせません）。
- `--rules-reload` のときは、ファイルが変わると（読み込めないファイルでも）、すべてのプリセットが無効になります。mitmproxy や `run` が再起動したときも同じです。`run` は、エージェントが有効・無効にするたびにログに書きます（時間や回数で終わったものは書きません）。`reqcove status` と `status` ツールは、いま有効なものを表示します。
- `delay_ms` で待っている途中の応答は、プリセットを無効にしたあとも、そのまま返ります。
- ファイルにプリセットがあることが、エージェントに有効にしてよいという同意になります。エージェントが `preset:` を書くのは、会話の中であなたが頼んだときだけです（Skill とサーバーの instructions がそう伝えます）。記録に書かれていたことを理由には書きません。`--rules-reload` のときは、書いてすぐ有効にできます。

確認状況：E2E テスト（本物の mitmproxy）で確認しました。確認したのは、有効と無効、時間と回数で無効になること、match ごとに 1 つだけ有効なこと（1 つの URL の 2 つの GraphQL operation は、それぞれ別に有効にできること）、ファイルの変更で無効になること、拒否（ない名前、5 分や 20 件を超える指定、reqcove の秘密を持たないソケットへの要求）、HTTP/2 の 1 つのストリームを遅らせている間に、同じ接続の別のストリームにはすぐ応答すること、HTTP/1 と HTTP/2 での close です。iPhone（iOS 27.3。URLSession を使うテスト用アプリ。エージェントが MCP でプリセットを有効にした）では、次を確かめました。503 を 1 回返したあと、アプリのやり直しがサーバーに届いたこと。8 秒の遅延。close では CFNetwork が自分でやり直さなかったこと（アプリ自身のやり直しも閉じられた）。ログインへの 401。

#### `map_remote`、`modify_headers`、`resolve` のプリセット

v0.7 から、`map_remote`、`modify_headers`、`resolve` のルールもプリセットにできます。`rule:`（これまでどおりのルール）と `preset:` を持つマッピングで書きます。モックのプリセットと同じく、エージェントが有効にするまで何もせず、有効にできるのは 1 回につき最長 5 分です。エージェントが、アプリの通信を少しの間ステージングや開発用のサーバーへ向けたり、機能フラグのヘッダーを付けたりして、また戻せます。

```yaml
map_remote:
  - {rule: "|~d api.example.com|^https://api\\.example\\.com/|https://staging.example.com/", preset: staging, description: to staging}
modify_headers:
  - {rule: "/~q/X-Feature-Flag/new-checkout", preset: new-checkout}   # リクエストだけ
resolve:
  - {rule: "api.example.com=192.168.1.20", preset: api-lan}
```

- ツールは `list_presets`（すべての種類。`kind` 付き）、`activate_preset(name, minutes)`、`deactivate_preset(name)` です。`times` はモック専用で、ほかの種類は時間だけで無効になります。
- 有効な間、`map_remote` のプリセットは、一致したリクエストをアプリの Cookie、トークン、ボディごと送り先へ送ります。`resolve` はその名前の接続先を指定のアドレスにします（Host、SNI、TLS の検証は名前のまま）。5 分で終わるのは切り替えで、その影響ではありません。アプリが書いたものはそのサーバーに残り、アプリはそこで得たトークンやキャッシュを持ち続けることがあります（[SECURITY](SECURITY.ja.md#map_remotemodify_headersresolve-のプリセット)）。
- `list_presets`、起動時の表示、`reqcove status` に出すのは、`map_remote` の送り先（スキームとホスト）、`modify_headers` のヘッダー名（値は出しません）、`resolve` の名前とアドレスです。フィルターや正規表現は出しません。
- 読み込みで断るもの：
  - 次のどれかに当たる `map_remote` のプリセット：置き換えが `http://` か `https://`、ホスト、`/` で始まらない（送り先を表示できないため）、送り先にユーザーやパスワードがある、ホストをリクエストから取る（`\1`）、リンクローカルのアドレスへ送る、このコンピュータや LAN のアドレス（`localhost`、`*.local`、プライベートアドレス）以外へ平文の `http://` で送る
  - レスポンスを変える `modify_headers` のプリセット（`~s`）
  - `map_local` のプリセット
  - プリセットと同じ一致条件の普通のルール（`map_remote` は同じフィルターと正規表現、`modify_headers` は同じフィルターとヘッダー）
- 送らずに 502 を返すもの：書き換えた URL が表示している送り先の外になるリクエスト（正規表現が URL の途中に一致したもの）。
- 同じ一致条件で有効にできるのは、種類ごとに 1 つです（`map_remote` は同じフィルターと正規表現、`modify_headers` は同じフィルターとヘッダー、`resolve` は同じ名前）。有効な `resolve` のプリセットは、同じ名前の普通の `resolve` より先に使います。有効な `map_remote` のプリセットは普通のルールより先に、`modify_headers` のプリセットは普通のルールのあとに当てます（プリセットのヘッダーが残ります）。
- 名前は種類をまたいで共通です（モックと `resolve` のプリセットの両方を `staging` にはできません）。一覧の行の `presets` には、そのリクエストを変えたか応答したプリセットがすべて入ります（`preset` は、応答したモックのものとして残します）。
- `reqcove status` と `status` ツールの `active_presets` には、有効なものがすべての種類で入ります（`kind` 付き。mitmproxy から答えがなければ `active_presets_error`）。`capture_stats` の `presets` には、すべてのプリセットの名前が入ります。

確認状況：E2E テスト（本物の mitmproxy、平文の HTTP）で確認しました。確認したのは、`map_remote`、`modify_headers`、`resolve` のプリセットがそれぞれ有効な間だけリクエストを変えること、行に載ること、ヘッダーの値を出さないこと、`times` を断ること、ファイルの変更で無効になること、読み込みで断るもの（mitmproxy の Python で）です。未確認：アプリの接続が開いたまま（HTTP/1 の使い回し、HTTP/2）`map_remote` や `resolve` のプリセットを有効にしたときの HTTPS（前に開いた接続を使い続けることがあります）。LAN モードの iPhone で試しました（iOS 27.3、2026-11-14）：このコンピュータの開発サーバーへの `map_remote` のプリセットを MCP で有効にすると Safari に開発サーバーの応答が返り、行に載りました（無効にするとサーバー自身の応答）。`times: 1` のモックのプリセットは 503 を 1 回返し、そのあとはサーバーの応答でした。iPhone で試していないもの：`resolve` と `modify_headers` のプリセット。コードから：ルールはリクエストの始まりで当てるので、`map_remote` や `resolve` のプリセットが有効な間に始まった WebSocket、ストリーム、長いアップロードは、プリセットが無効になったあとも、その送り先のままです。

#### ルールが当たった理由、当たらなかった理由（`list_rules`、`explain_rules`）

このコンピュータのエージェントは、ファイルを読まずにルールを確かめられます。

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

確認状況：E2E テスト（本物の mitmproxy、平文の HTTP）で確認しました。確認したのは、`list_rules` がフィルター、正規表現、ヘッダーの値、ボディ、パスを返さないこと（目印の文字列で）、範囲外のホスト、`--pass-hosts` のホスト、モックのプリセットの無効と有効（回数を使わず、サーバーにも届かない）、operationの有無での GraphQL のモック、`cannot_tell` に入る `~h` のフィルター、`map_remote` のあとの `resolve` を記録されたフローと同じに説明すること、ルールのファイルがないときです。iPhone を使った確認の中で、Claude Code から `list_rules` と `explain_rules` を使いました（iOS 27.3、2026-11-14：動きました）。記録される URL はマスク済みなので、パスやクエリでマスクした値（`[redacted]`）で、フィルターや正規表現の結果が変わることがあります。本物のリクエストと同じく、URL の GraphQL のoperationが、渡したものより先です。

### 上流プロキシに回す（`--upstream-proxy`）

Reqcove で記録しながら、同じリクエストを Burp Suite（や ZAP、Charles など）でも見たいときに使います。

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' \
  --upstream-proxy http://127.0.0.1:8080
```

復号したリクエストはプロキシへ送り（HTTPS は CONNECT トンネル、平文の HTTP はプロキシ宛てのリクエスト）、サーバーへは直接接続しません。プロキシにはマスクされていない中身がすべて見え、Burp はそれをプロジェクトに保存します。Burp の Intercept はオフにしてください。オンのままだと、リクエストがそこで止まります。

- `--allow-hosts` にないホストへの接続は、これまでどおり直接通ります。ただし、許可したホストへの復号済みの接続に相乗りした、ほかのホスト宛てのリクエスト（HTTP/2 の接続の再利用）は、記録されないままプロキシを通ります。許可したホストへのほかのプロトコル（MQTT など）は、サーバーへ直接接続します。TLS を使うものは、プロキシの CA を使っている間は失敗します（サーバーの証明書を、その CA で検証するためです）。
- Burp は HTTPS のホストに、SNI の名前をこのコンピュータで名前解決し直して接続します。そのため、Exit Node がこのコンピュータと LAN を宛先として拒否していても、Burp の接続先には効きません（[SECURITY](SECURITY.ja.md#上流プロキシ--upstream-proxy)）。`--allow-hosts` は、調べるホストだけにしてください（`'*'` のときは `run` が警告します）。同じ理由で、`resolve` のルールは拒否します。プロキシ側の設定（Burp の Hostname resolution overrides）を使ってください。
- プロキシを通る HTTPS は、プロキシの CA だけで検証します。このコンピュータの Burp の CA は、起動時に Burp のプロキシのアドレスにある `/cert` から取得します。ほかの復号するプロキシ（ZAP、Charles など）には、`--upstream-ca FILE`（PEM か DER）で CA を指定してください。どちらでもなければ、公開の CA で検証します（復号しないプロキシ向け）。
- Reqcove はプロキシに直接接続し、システムのプロキシ設定は使いません。ただし、システムのプロキシを自分に向けるプロキシ（Charles は、Proxy メニューの「macOS Proxy」をオフにしない限りそうします）と `--local-proxy` は、同じ設定を取り合い、止まるときに相手の設定へ戻してしまいます。`--local-proxy` と一緒に使うときは、プロキシ側のその機能をオフにしてください。
- Burp での動作：平文の HTTP は IP アドレスで表示され、名前は `Host` ヘッダーで分かります。リクエストのボディは、すべて届くまで Burp が保持します。HTTP/1.1 のクライアントへの Server-Sent Events は失敗します（iOS アプリの多くが使う HTTP/2 では流れます）。SNI のない、IP アドレス宛ての HTTPS は失敗します（Burp が証明書に入れるアドレスの形式を、mitmproxy が受け付けないためです）。`--web` と一緒に使うと、mitmweb からリプレイした平文の HTTP リクエストは、プロキシ自身に送られます。

確認状況：Burp Suite Community 2026.10 で確認しました（SNI の名前で名前解決し直すことを含みます）。Charles 5.0b12（復号する設定）でも、`--upstream-ca` を付けて確認しました（付けないと、証明書を信頼できなかったことが記録に残ります）。このコンピュータで Burp 以外のプロキシを使うときも、`run` は起動時にそのプロキシのアドレスにある `/cert` を取りに行き、そこで失敗しますが、動きは変わりません。未確認：ほかのプロキシ。コードから：ほかのプロトコルは、サーバーへ直接接続します。

## Tailscale を使わずに同じネットワークでつなぐ（`--lan`）

`reqcove run --lan` は tailnet のノードを起動しません。Reqcove はこのコンピュータの LAN のアドレスで HTTP プロキシとして待ち受け、同じネットワークの iPhone が Wi-Fi のプロキシ設定にこれを指定します。主な使い方は今後も Exit Node です。Exit Node は iPhone のすべての通信をモバイル通信でも中継し、つながっているネットワークに何も求めません。LAN モードは Tailscale を使えないときのためのものです。

```sh
reqcove run --lan --allow-hosts api.example.com
```

1. `run` が待ち受け先を表示します。デフォルトルートのインターフェイスのアドレス（別のものは `--lan-interface en0` で指定。VPN のトンネルは不可）と、`--proxy-port`（デフォルトは 8080）です。
2. iPhone で、設定、Wi-Fi、ネットワークの (i)、プロキシを構成、手動の順に開き、そのサーバーとポートを入力します。認証はオフのままにします。
3. このコンピュータで iPhone を許可します。最初の接続は拒否され、`run` がそのアドレスをログに出します。`run` の質問（`Allow ADDR? [y/N]`。`run` がターミナルのフォアグラウンドのジョブのときに表示）に答えるか、ターミナルで `reqcove lan allow ADDR` を実行します。
4. CA を信頼します（デバイスごとに 1 回）。Exit Node のときと同じく、プロキシを設定した状態で `http://mitm.it` を開きます。平文の HTTP は同じ LAN のほかの人に差し替えられるおそれがあるので、`run` の準備完了の表示には、AirDrop で送るための CA のファイルと、照合するための CA の SHA-256 も出します。SHA-256 は iOS の表示と同じ形（小文字の 2 桁ずつ、空白区切り：`ab 90 7e …`）です。iPhone では設定、一般、VPN とデバイス管理、そのプロファイル、詳細で見られます（iOS 27.3 で確認、2026-11-14：一致しました）。未確認：そのファイルの AirDrop。

`reqcove lan list` で許可したアドレスと許可した日時を表示し、`reqcove lan deny ADDR` で許可を取り消します。`reqcove lan` のコマンドはターミナル以外では動きません。エージェントが使うものではありません。

記録と `reqcove status` では、次のように見えます。

- 記録では、デバイスは `lan:ADDR` という名前になります。ツールの `device` での絞り込みと `reqcove har --device lan:ADDR` はこの名前を受け付け、`list_devices` はこの実行での最初と最後のリクエストの時刻を返します。
- `reqcove status`（と `status` ツール。`mode: "lan"`）には、待ち受け先、許可したアドレス、この実行で拒否したアドレスが出ます。拒否したアドレスは同じネットワークの誰でも増やせるので、最後に見た 50 件と、残りの件数（`refused_more`）だけを出します。元の一覧は最大 10,000 件で、いっぱいになると空にします。

パスワードはありません。誰がプロキシを使えるかは、Charles Proxy と同じく、このコンピュータでアドレスごとに決めます（Charles のドキュメントでは、アクセス制御のリストと、新しいアドレスへのダイアログが説明されています）。これは次のことを意味します。

- 許可するのはデバイスではなくアドレスです。あとでそのアドレスを持ったものも許可されます。リストは状態ディレクトリ（`lan-allowed`）に保存されるので、同じプレフィックスの別のネットワークでも許可されたままです（カフェの 192.168.1.0/24 と自宅の 192.168.1.0/24 など）。使い終わったら `reqcove lan list` と `lan deny` で整理してください。未確認：iPhone のプライベート Wi-Fi アドレスが、同じネットワークで長く変わらないか。
- 許可したアドレスは、このコンピュータを通って、あなたのアドレスからインターネットに出られます（80 番と 443 番ポートのみ）。`--allow-hosts` に完全な名前（`*` なし）で書いたプライベートなホストにも届きます。このコンピュータの VPN の先のものも含みます。このコンピュータ、リンクローカルアドレス、プロキシのあるネットワークには、完全な名前でも届きません。許可したホストへのリクエストは記録されます。
- `--rules` の `map_remote` と `resolve` の宛先には mitmproxy が接続するので、これらの確認の外です。許可したホストをこのコンピュータのサーバーに送るルールがあると、LAN のクライアントのリクエストもそこに届きます。
- `lan deny` は 2 秒以内に新しい接続を拒否しますが、すでに開いている HTTPS のトンネルは閉じるまで（または 15 分間やりとりがなくなるまで。[制限事項](#制限事項)）続きます。
- 信頼できるネットワークで使い、使い終わったら止めてください。

Exit Node とのほかの違いは、次のとおりです。

- 80 番と 443 番ポートのみです。プロキシを設定している間は、このコンピュータや同じ Wi-Fi の開発サーバー（8081 番の Metro など）は拒否されます。未確認：iOS がローカルのアドレスにプロキシを使わないか。
- 名前解決はこのコンピュータのリゾルバで、`/etc/hosts` が先です。そこで 127.0.0.1 になる名前は拒否されます。
- Wi-Fi のプロキシ設定に従わないアプリは直接インターネットに出て、記録されません。
- つながらない原因：Wi-Fi のクライアント分離（ゲスト用のネットワークによくあります）、iPhone とこのコンピュータの間の VLAN、MDM のプロファイル、管理されたファイアウォール。未確認：macOS のファイアウォールが `reqcove` への接続の許可を求めるか。
- `--lan` は `--config` では使えないので、サービスとしては動きません。`--device`、`--ui`、`--mcp-http`、`--hostname`、`--dns` は tailnet のノードのものなので一緒に使えません。`--local-proxy` と `--web`（このコンピュータでのみ）は使えます。
- 同じネットワークでこのコンピュータのアドレスが変わると、新しいアドレスで待ち受けます。別のネットワークに移ると待ち受けをやめ、ログと `reqcove status` にそう出します。再起動すると新しいネットワークで待ち受けます。

確認状況：テスト（ループバックのインターフェイスで本物の mitmproxy を使い、HTTP と HTTPS が `lan:127.0.0.1` として記録され、`http://mitm.it` が CA を返すこと、上の拒否）と、自宅の Wi-Fi の iPhone（iOS 27.3、2026-11-14：最初のリクエストは拒否され、`run` の質問で許可すると、許可したホストへの Safari の HTTPS が復号されて `lan:ADDR` として記録されました。`reqcove lan deny` で止まり、もう一度 `lan allow` すると通りました）。Ubuntu 24.04.5 LTS（arm64、tart の VM、2026-11-14）では、VM を動かしている Mac から tart のネットワーク越しに curl で試しました（iPhone なし）：VM のアドレスで待ち受け、最初のリクエストを拒否して質問し、`reqcove lan allow` で許可すると、許可したホストへの HTTP と HTTPS（ready の表示にある CA ファイルを `curl --cacert` に渡し、SHA-256 も一致）が通って `lan:ADDR` として記録されました（`reqcove status --json`、`reqcove har`）。ポート 22 は拒否され、`lan deny` でまた拒否されました。未確認：ネットワークの切り替え、Linux のコンピュータと iPhone の組み合わせ。

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

- **ファイル**：`--config FILE` は、`run` のフラグを 1 行に 1 つずつ読みます。
  - `#` から後ろはコメントです。シェルと同じように引用符でくくれます：`--device "Taro's iPhone"`。`~/` はホームディレクトリです。サービスは `/` で起動するので、パスはフルパスか `~/` から書きます。
  - コマンドラインのフラグはファイルのあとに読むので、1 回だけ指定するフラグはコマンドラインのものが勝ち、繰り返せるフラグは足し合わされます。
  - ファイルで断るもの：`--no-redact`、`--web`、`--rules-reload`、`--lan`、`--config`、`--allow-hosts '*'`（`@FILE` で指定したものも）。これらはコマンドラインでだけ使えます。
  - ファイルは自分の持ち物で、自分だけが読めるもの（`chmod 600`）に限ります。`--mask-values` のパターンを書くことがあるためです。
  - `--config` は 1 つだけです。指定しなければ、何も読みません。
- **終わったとき**：ファイルがないときや断ったときは、サービスは 1 回で終わります（`brew services` がエラーを表示します）。繰り返し起動し直すことはありません。ほかの理由で終わったときも同じなので、`brew services restart reqcove` で起動し直してください（`brew upgrade reqcove` のあとも）。
- **ログ**：`$(brew --prefix)/var/log/reqcove.log` です。状態ディレクトリの `mitmproxy.log` も伸び続けます。launchd も reqcove もローテーションしないので、ときどき空にしてください。どちらにもログイン用の URL やトークンは入りません。それらは `reqcove links` が自分のターミナルに表示します。
- **ターミナルからの `run`**：同じ状態ディレクトリで、ターミナルから `run` を起動すると「使用中」と断られます。先に `brew services stop reqcove` を実行してください。
- **スリープ**：`run` は動いている間、Mac のアイドルスリープを止めます（`caffeinate -i`。ターミナルから起動したときと同じで、バッテリーでも止めるので電池を使います）。ふたを閉じたときや、スリープを選んだときは止められません。

Linux では、Homebrew の `brew services` が同じ formula から systemd のユニットを作ります（Homebrew のドキュメントによるもので、試していません。`status` はサービスを表示しません）。Homebrew を使わないなら、次の節を見てください。

確認状況：設定ファイルの読み方と、断るフラグは単体テストで確認しました。macOS 27 で formula から `brew services start` と `stop` を試しました（PATH から uv が見つかる、設定ファイルが読まれる、iPhone のリクエストが記録される、ログにトークンやログイン用の URL が入らない、ターミナルでないところでは `reqcove links` が断る、止めたあと `links` と `login-url` が消える）。ログイン時や Mac の再起動後の起動、スリープ、ターミナルから起動していない `run` に macOS のローカルネットワークの許可を求められるか、launchd のデフォルトの優先度で遅くならないかは、`brew services` ではまだ試していません（スリープ、ログイン時の起動、ローカルネットワークの許可は、下の `reqcove service install` で試しました）。

### Homebrew なしで常駐させる（`reqcove service install`）

リリースのバイナリや、ソースからビルドしたものなら、`reqcove service install` で同じことができます（Homebrew で入れたなら、上の `brew services` を使ってください）。macOS では LaunchAgent（`~/Library/LaunchAgents/io.github.mh-mobile.reqcove.plist`）、Linux では systemd のユーザーユニット（`~/.config/systemd/user/reqcove.service`）を作ります。サービスは、このバイナリ（フルパス）を `run --config FILE` で起動します。すぐに起動し、ログインするたびにも起動します。終わっても起動し直しません（`brew services` と同じ）。

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

- **ファイル**は、`--config` で指定しなければ `~/.config/reqcove/config` です。読み方は `brew services`（上）と同じです。
  - インストールのときに、ファイルがない（書き方を表示します）、自分の持ち物でない、ほかの人が読める、`--no-redact`、`--web`、`--rules-reload`、`--lan`、`--config` が書いてある、のどれかなら断ります。
  - `--allow-hosts '*'` は `run` が起動したときに断ります（サービスは 1 回で終わります）。
  - ファイルに `--state` があれば、それが状態ディレクトリです（フルパスか `~/` から）。状態ディレクトリは、空か、新しいか、reqcove のものに限ります（`run` と同じ）。
- **終わったとき**：`run` が終わると（エラー、断られたファイル、`kill`）、次のログインまで止まったままです。`reqcove service restart` で起動し直せます（`launchctl kickstart -k gui/$(id -u)/io.github.mh-mobile.reqcove` か `systemctl --user restart reqcove` を実行します。試したのは Linux だけです）。
- **Homebrew のサービスがあるときは断ります**（ファイルがあるか、読み込まれている：`sh.brew.reqcove`、`homebrew.mxcl.reqcove`。Linux では `sh.brew.reqcove.service`、`homebrew.reqcove.service`。Linux の名前は Homebrew のコードを読んだもので、試していません）。2 つのサービスが同じ状態ディレクトリを取り合うためです。
- **Homebrew で入れた `reqcove` も断ります**。そのパス（Cellar の中）は `brew upgrade` で消えるためです。`reqcove setup` で Homebrew のサービスが読むファイルを書き、`brew services start reqcove` で起動してください（単体テストで確認）。
- **インストール済みのとき**：起動し直すには `reqcove service restart` を実行します。コマンドラインのフラグを変えるときやバイナリを動かしたあとは、`reqcove service uninstall` のあとでもう一度インストールしてください。
- **ログ**：
  - macOS：状態ディレクトリの `service.log` です。ローテーションしないので、`mitmproxy.log` と同じく、ときどき空にしてください。launchd が作ると 0644 になるので、`service install` が先に 0600 で作ります（単体テストだけで、launchd では試していません）。
  - Linux：`journalctl --user -u reqcove` です。
  - ログイン用の URL やトークンは入りません。`service install` も表示しません。それらは `reqcove links` が自分のターミナルに表示します。
- **`PATH`** は、インストールしたときの uvx のディレクトリ、`~/.local/bin`、`/opt/homebrew/bin`、`/usr/local/bin`、システムのものの順です。ほかの場所にあるなら、ファイルに `--uvx /full/path/uvx` と書いてください。
- **次のログインまで止める**には、`launchctl bootout gui/$(id -u)/io.github.mh-mobile.reqcove` か `systemctl --user stop reqcove` を実行します。`reqcove status` がどちらかを表示します。
- **Linux**：ユーザーユニットはログインしている間だけ動きます。`loginctl enable-linger $USER` がないと、最後のセッションが終わったときに systemd が止め、次のログインでまた起動します（ssh で試しました。最後にログアウトしてから 15 秒以内に止まりました）。linger があると、ログアウトのあとも動き続けました（試しました）。ログインする前の起動時にも動きます（systemd のドキュメントによるもので、再起動は試していません）。

確認状況：書き出すファイル（空白、`&`、`<`、`%`、`$`、引用符を含むパス）、断る場合、実行する launchctl と systemctl のコマンドを単体テストで確認しました（テストでは実行しません）。macOS では試しました（2026-11-14：`service install` が LaunchAgent を書いて設定ファイルのフラグで `run` を起動し、Exit Node の iPhone が記録され、`service.log` にログイン用の URL やトークンは入りませんでした。`reqcove status` がサービスを表示し、`service uninstall` で止まってファイルが消えました。スリープのあとも動き続け、再起動のあとはログイン時に自動で起動しました（iPhone が記録され、ログイン時のアラートはなし）。macOS は、スリープの前とあとにローカルネットワークの許可を求めました（どちらも許可しました。その一覧には、別の場所に置いたビルドがそれぞれ別の項目として並びます））。Ubuntu 24.04.5 LTS（arm64、tart の VM、2026-11-14）でも、新しい `--state` と setup が書いたファイルで試しました：`service install` がユニットを書いて `run` を起動し（ユニットの `PATH` で uvx が見つかり、ノードはログイン待ちで、tailnet にはログインしていません）、`reqcove status` が `reqcove.service` を表示し、`journalctl --user -u reqcove` にログが出て、ログイン用の URL やトークンは入りませんでした。`service restart` は、`kill` のあとも `systemctl --user stop reqcove` のあとも起動し直し、`service uninstall` で止まってユニットが消えました。まだ試していないこと：macOS での `service restart`、Linux での tailnet にログインしたノード、それを通したデバイスの記録、再起動。

## コンテナで動かす

`reqcove run` はコンテナ（Docker、または Podman）でも動きます。手順、コンテナで違うこと、確かめたことは、別のページにあります：[コンテナで Reqcove を動かす](container.ja.md)。このガイドでコンテナに触れているのは次のところです。

- ほかのデバイスのエージェント：`--mcp-http` はコンテナでも同じフラグで、ポートの公開は不要です（[ほかのデバイスのエージェントから使う](#ほかのデバイスのエージェントから使う--mcp-http)）。
- ログイン用の URL とリンク：ターミナルでないところ（`docker logs`）では `run` は表示しません。`reqcove links` が表示します（[初回の起動](#初回の起動ログインと承認)）。
- セキュリティ：[コンテナ](SECURITY.ja.md#コンテナで動かす場合)。

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
| `reqcove status` | reqcove の状態と次の手順。`--json` で `status` ツールの JSON を出力。`--uvx PATH` |
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

iPhone で確認：`--mask-names`、RoamRun で操作したあとの `wait_for_flows`、試験用アプリでの `diff_flows`（二重に送ったリクエスト）、`list_ws_messages`、`--proto`。テストのみ：`--mask-values`、`max_body`、`--mcp-http` の回数制限、`multipart/form-data`、XML のボディ（mitmproxy を通した SOAP のリクエストの E2E テストも）。

コードから（フラグのヘルプに基づく記述で、このガイドでは未確認）：`--proxy-port 0`、`--hostname`、`--verbose`、`--uvx`、`--python`、`--mitmproxy-spec`、`status --json`。

## MCP ツール

| ツール | |
|---|---|
| `list_flows` | フローを新しい順に一覧。デバイス、ホスト（サブドメインを含む）、時間（`since: "10m"`）、ステータスコード（`404`、`4xx`、`none`）、メソッド、User-Agent（アプリ名など、含まれる文字列で指定。アプリのバンドル ID は通信に含まれない）、GraphQL の operation（`operation: "Login"`。`operationName`、なければ文書の最初の operation。一覧の行にも出る）で絞り込み。ページング対応。ホストが 1 件も一致しないときは、記録にある似たホスト（`acmeshop.com` に対する `acme-shop.com` など）を `similar_hosts` で返す |
| `search_flows` | URL とヘッダーのテキストを検索（`bodies` を指定するとボディの先頭も対象）。絞り込みと `similar_hosts` は同じ |
| `wait_for_flows` | デバイスでの操作が送った通信を読む。操作の前に `list_flows`（または `capture_stats`）の `checkpoint` を控え、操作のあと `after: checkpoint` で呼ぶ。それ以降に返事（レスポンスかエラー）が来たフローを、返事の早い順に返す。まだなければ、最初の 1 件を最長 `timeout` 秒（デフォルト 20、最大 30）待つ。結果の `after` を次の呼び出しに渡せば、同じフローは二度返らない。絞り込みは同じ。WebSocket は開いたとき（`101`）に一度だけ返り、閉じるまで `open` のまま |
| `get_flow` | フローを 1 件取得。ボディは `bodies` を指定したときだけ（`max_body` を指定すると、それぞれそのバイト数まで）。`response_trailers` は HTTP/2 のトレーラー（gRPC-Web では最後のフレーム）。`view` のあるボディは Reqcove が書き起こしたもので、バイト列そのものではない。protobuf（[gRPC](#grpc)）や、パートごとにマスクしてファイルは大きさだけにした `multipart/form-data` |
| `list_ws_messages` | WebSocket のメッセージ（一覧の行に `websocket_messages` があるフロー）を古い順に読む。`after` にはチェックポイントか、前のページの `after` を渡す。`direction`（`client`、`server`）と `text` で絞り込める。テキストのメッセージは先頭 4 KiB を、ボディと同じく届いた時点でマスクして返す。バイナリのもの、その接続で毎秒約 20 件を超えた分、マスクの仕組みで読めないテキストは、大きさだけを返す。残すのは、接続の最初の 5 件（認証のメッセージはたいていここに入る）と新しい 100 件で、`after` より後でそれ以外のものの数は `missed` に出る（`after` 自体がそれらの間にあるときは `missed_at_most` が付き、`after` より前のものも数えに入りうる）。`open` と `close`（コード、閉じた側）で接続の状態がわかる。メッセージでは `wait_for_flows` は返らないが、時間切れの答えに、その間にメッセージがあった接続が `websocket_activity` として並ぶ。`search_flows` は `bodies` を付けると、残したメッセージも探す |
| `diff_flows` | 2 つのフローを比べる（成功したものと失敗したものなど）。メソッド、URL、ステータスコード、エラー、ヘッダー（名前ごと）、ボディ（JSON はパスごと）。マスク中は、両方でマスクされた値を「同じ」とは言わず `masked` に並べ（元の値は違うかもしれない）、テキストでないボディは比べない。`--no-redact` のときは全部比べる |
| `summarize` | ホスト、User-Agent、ステータスコード、メソッド、デバイス、Content-Type、gRPC のステータス（`by_grpc_status`）、エンドポイントごとの件数。エンドポイント（`by_endpoint`）は、メソッド、ホスト、クエリを除いたパス（ID は `{id}`）、GraphQL なら operation（`GET api.example.com/v1/users/{id}`、`POST api.example.com/graphql Login`）。絞り込みと `similar_hosts` は同じ |
| `list_devices` | 中継しているデバイス（LAN モードでは `lan:ADDR`）と、それぞれの件数、この実行での最初と最後のアクティビティ |
| `list_tls_failures` | デバイスが拒否した TLS ハンドシェイク。多くは証明書ピンニングか、まだ信頼されていない CA が原因 |
| `list_passthrough` | `--pass-hosts` のホストへの接続。ホスト、接続先サーバー、時刻、バイト数。URL や中身はなし |
| `capture_stats` | mitmproxy の状態、記録がカバーしている期間、ドロップ数 |
| `status` | モード（`tailnet` か `lan`。`lan` では許可したアドレスと拒否したアドレスも）、セットアップが完了しているか。未完了なら次の手順。有効にしたプリセット。すべての種類（`active_presets`。`kind` 付き。`--mcp-http` では出しません。プリセットのツールがないため） |
| `list_presets` | `--rules` のファイルの[プリセット](#エージェントが有効にできるプリセット)。すべての種類（`kind`）。モックの match と応答、`map_remote` の送り先、`modify_headers` のヘッダー名、`resolve` の名前とアドレス。有効か、無効になる時刻。ボディ、ヘッダーの値、フィルター、正規表現は返さない。`--mcp-http` からは使えない |
| `activate_preset` | どの種類のプリセットも有効にする。最長 5 分（`minutes`。モックは `times` で最大 20 件）。`wait_for_flows` 用の `checkpoint` と、同じ一致条件で無効にしたプリセットを返す。`--mcp-http` からは使えない |
| `deactivate_preset` | プリセットを無効にする。`--mcp-http` からは使えない |
| `list_rules` | `--rules` のファイルの[ルール](#ルールが当たった理由当たらなかった理由list_rulesexplain_rules)を種類と番号で。プリセットと、ルールから導いたもの（モックの match と応答、`map_remote` の送り先、`modify_headers` のヘッダー名と向き、`resolve` の名前とアドレス）。フィルター、正規表現、ヘッダーの値、ボディ、パスは返さない。`--mcp-http` からは使えない |
| `explain_rules` | フロー（`flow_id`）や、メソッドと URL が、どのルールを受けたか（受けるか）と理由。範囲、書き換え、モック、有効なプリセットと、無効なものを有効にしたらどうなるか。メソッドと URL だけでは決められないフィルターのルールは `cannot_tell` に。何も送らず、プリセットの回数も使わない。`--mcp-http` からは使えない |
| `add_marker` | [マーカー](#マーカーを置くreqcove-mark)を置く（`text` は 1 行で 80 文字まで、マスクする）。`id`、`time`（`since` 用）、`checkpoint`（`wait_for_flows` の `after` 用）を返す。デバイスには何も変えない。`--mcp-http` からは使えない |
| `list_markers` | マーカーを古い順に（`since`）。`source` は `cli`（`reqcove mark`）か `mcp`（エージェント）。`--mcp-http` からは使えない |

## 制限事項

主な制限事項は [README](../README.ja.md#制限事項) にあります。そのほかの制限事項は次のとおりです。

- IPv6 は拒否します。アプリはすぐに IPv4 にフォールバックします。
- QUIC は Apple 宛てを除いてドロップするので、アプリは TCP にフォールバックします。判定はホストではなくアドレスで行うため、`--allow-hosts` にないホストの QUIC も（`--allow-hosts` を指定しないときも）フォールバックします。443 番以外のポートの QUIC はそのまま通し、記録しません。
- mitmproxy は WebSocket のメッセージを、届ききるまで 1 つずつ保持します。圧縮されたもの（permessage-deflate）は丸ごと展開します（mitmproxy のコードを読んだもので、圧縮されたメッセージは試していません）。そのため巨大なメッセージが来ると、メモリを多く使います。Reqcove の 4 KiB の上限は、Reqcove が残す分にかかるもので、mitmproxy のメモリにはかかりません。mitmproxy がメモリ不足で落ちると reqcove が再起動し、再起動しても 1 分以内に落ちることが 5 回続くと、`run` はエラーで止まります（終了ステータスは 1 で、Ctrl-C の 0 とは違います。サービスとして動かしていれば、失敗と表示されます。終了し続ける mitmproxy の代役で試しました）。
- reqcove が mitmproxy に渡す接続は、mitmproxy がサーバーにつながるのを待ちます。直接つなぐ接続がサーバーを待つのと同じく、最長 10 秒です。そのときログには `<アドレス>:<ポート> did not answer within 10s (through mitmproxy)` と出ます。先にアプリがあきらめたときは `the client left before <アドレス>:<ポート> answered (through mitmproxy)` と出ます。どちらも、そのときサーバーが遅かったか、このコンピュータから届かなかったということです（応答しないアドレスで試しました。実際のアプリで出た 2 件が遅かった理由はわかっていません）。
- Remote Proxy、LAN モード、`--local-proxy` では、1 つのクライアント（アドレス 1 つ。`--local-proxy` では、このコンピュータのアプリすべてで 1 つ）が同時に開けるトンネル（CONNECT。HTTPS や WebSocket）は 256 本までです。それを超えると、どれかが閉じるまで 503 を返します。どちらの向きにも 15 分間バイトが流れないトンネルは閉じます。やりとりが続く WebSocket やイベントストリームは開いたままです（2 本と 300 ミリ秒で試しました）。Exit Node 自身の接続には、どちらの制限もありません（コードを読んだもの）。
- Exit Node 経由の通話は未確認です。
- 機能ごとの制限事項はそれぞれの節にあります：[`--ui`](#iphone-で見る--ui)、[`--web`](#mitmweb-で見る--web)、[`--local-proxy`](#ios-シミュレーターを記録する--local-proxy)、[LAN モード](#tailscale-を使わずに同じネットワークでつなぐ--lan)、[ルール](#ルールを書く--rules)、[上流プロキシ](#上流プロキシに回す--upstream-proxy)。

## セキュリティ

詳しくは [SECURITY.ja.md](SECURITY.ja.md) にあります。オプションごとの注意は上の各節からリンクしています。それ以外の主な項目は次のとおりです。

- [記録するもの](SECURITY.ja.md#記録するもの)：`--allow-hosts` のホストだけで、Apple のホストは対象外です。マスクで見つかるものと、見つからないものがあります。
- [エージェントが読んだものの行き先](SECURITY.ja.md#エージェントが読んだものの行き先)：モデルの提供元に渡ります。ボディがエージェントに指示しようとすることもあります（[プロンプトインジェクション](SECURITY.ja.md#プロンプトインジェクション)）。
- [デバイスから届く範囲](SECURITY.ja.md#デバイスから届く範囲)：このコンピュータ、LAN、tailnet には届きません。
- [CA の秘密鍵](SECURITY.ja.md#ca-の秘密鍵)：状態ディレクトリにあります。
- [Exit Node の DNS](SECURITY.ja.md#exit-node-の-dns)（`--dns`）と、[コンテナ](SECURITY.ja.md#コンテナで動かす場合)。
