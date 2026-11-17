# 互換性

[English](COMPATIBILITY.md) · [README](../README.ja.md)

**v1.0.0 から適用します。** それより前の v0.x では、ここに書いたことでもマイナーリリースで変わることがあり、実際に変わったものもあります。

このページでは、メジャーバージョンの間は変わらないもの、どのリリースでも変わりうるもの、変更の知らせ方を説明します。一覧は記憶ではなくコード（MCP サーバーが登録するツール、各コマンドのフラグ、ルールファイルの読み込み処理）から取りました。テストで確かめた点はその節の最後の行にそう書いています。それ以外はコードを読んで書いたものです。

1. [バージョン](#バージョン)
2. [メジャーバージョンの間は変わらないもの](#メジャーバージョンの間は変わらないもの)
3. [変わりうるもの](#変わりうるもの)
4. [`reqcove mcp` と別のバージョンの `run`](#reqcove-mcp-と別のバージョンの-run)

## バージョン

v1.0.0 から、バージョンは `major.minor.patch`（[セマンティック バージョニング](https://semver.org/lang/ja/)）です。

- パッチリリース（1.0.1）は修正です。このページで変わらないとしたものは、それまでどおり動きます（セキュリティ修正は例外。下記）。
- マイナーリリース（1.1.0）は追加です。ツール、省略できる入力、出力のフィールド、コマンド、フラグ、ルールのキーが増えることがあります。非推奨にすることはあっても、削除はしません。
- メジャーリリース（2.0.0）では、変わらないとしたものを削除・変更することがあります。その前に必ず非推奨にします。

### 非推奨

- マイナーリリースで知らせます。CHANGELOG の「Deprecated」に、代わりに使うものと一緒に書き、非推奨のツールは説明の先頭を「Deprecated」にします。
- 削除されるまでは、それまでどおり動きます。削除は早くても次のメジャーリリースです。

### セキュリティ修正

古い動作のままでは利用者が危険にさらされる場合、セキュリティ修正はどのリリースでも、パッチリリースでも、動作を変えることがあります。受け付けていたもの（フラグの値、ルール、`--config` の行）を拒否する、マスクを増やす、ツールの答えに含めるものを減らす、機能を止める、といった変更で、このページで変わらないとしたものも対象になります。メジャーリリースまで待つことはしません。CHANGELOG の「Security」に、何が変わり、何をすればよいかを書きます。

### v1.3 で増えたものと変わったもの

増えたもの（それぞれ下の該当する場所にあります）：`reqcove restart`（`--web` も）とその ctl の op `restart`（その `web` フィールド）、`status` の `mitmweb` と `mitmweb_this_start_only`、`reqcove console --end`（op `console-end`）と `--tailnet`（`console` の `tailnet` フィールド。答えは `addr`）、`console` の答えの `file`、`save` の `confirm` フィールド、マーカーの `source` の `console`、`approved_in` の `console on NAME (tailnet)`、ホストのないホストのファイルを受け付けること、`capture save` が config に足すことのある 1 行と、そのとき作るホストのファイル、`reqcove setup` が必ずホストのファイルを書くこと。変わりうるもの（約束しないもの）：`reqcove console` のページとその要求（`/api/…`）、`status` の `console_sessions`、`run --check-config`、再起動が引き渡すものと残すもの（[下記](#変わりうるもの)）。

v1.0 で約束したもののうち、v1.3 で変わったもの：

- **`--no-redact` でも 1 つのヘッダーはマスクします。** コンソールのセッションのヘッダー（`X-Reqcove-Session`）は Reqcove 自身の資格情報なので、ほかに何もマスクしない `--no-redact` でも、すべての記録でマスクします。上の条項によるセキュリティ修正です（CHANGELOG の「Security」）。することはありません。
- **ホストのないホストのファイルを受け付けます**（コメントだけ、または空）。ホストは増えません。v1.0 から v1.2 は拒否していました。また、`--pass-hosts`、`--rules`、`--upstream-proxy` は、フラグがあるかではなく、指定されたホストで確かめます。v1.2 が拒否したフラグの組み合わせが起動することがあります（たとえば、空のファイルの `--pass-hosts=@FILE` で `--allow-hosts` がないとき）。以前起動したもので、いま拒否するものはありません（コードから判断したものです。以前はホストのファイルにホストが必要だったので、フラグがあればホストがありました。新しく受け付ける場合は単体テストで確認）。

ここで変わらないとしたもののうち、ほかに変わったものはありません。ツールとそのフィールド、ルールのファイル、コマンドとフラグ、`status --json` のフィールドです。

## メジャーバージョンの間は変わらないもの

メジャーバージョンの間、ここに挙げたものは削除せず、意味も変えません。マイナーリリースで増えることはあります。

### MCP ツール

このコンピュータから `reqcove mcp` と `run` のソケットで使えるのは、次の 19 個です。

`status`、`list_flows`、`wait_for_flows`、`search_flows`、`summarize`、`get_flow`、`list_ws_messages`、`diff_flows`、`list_devices`、`list_tls_failures`、`list_passthrough`、`capture_stats`、`list_presets`、`activate_preset`、`deactivate_preset`、`list_rules`、`explain_rules`、`add_marker`、`list_markers`

v1.2 から、`reqcove mcp` だけに `request_capture_add`（`hosts`：ホスト名 1〜5 個）と `get_capture_request`（`id`）もあり、そこでは 21 個です。`run` のソケット自身の一覧にはなく、`--mcp-http` にもありません。どちらも頼みを返します：`id`、`hosts`、`state`（`pending`、`approved`、`applied`、`failed`、`denied`、`expired`。値は増えることがあります）、`created_at` と `expires_at`（RFC 3339）、`approved_in`（`terminal` か `dialog`。`reqcove console` からは `console` も。v1.3 からは、その tailnet のページから `console on NAME (tailnet)` も。NAME はデバイスのマシン名）、`result`（人が読むための文）、`approve`（保留の間、ユーザーが実行するコマンド）、`unmasked`（`run` が何もマスクしないとき、`--no-redact` で true）、`note`。

`--mcp-http` から使えるのは最初の 12 個（`status` から `capture_stats` まで）で、プリセット、ルール、マーカーのツールは使えません。`--mcp-http` の `status` には `active_presets` と `active_presets_error` がありません。そのサーバーは `/mcp` で答えます。ポートはノードの 8090 番です。認証は `Authorization: Bearer` で、トークンは `mcp-token`（下の状態ディレクトリ）にあります。

v1.0.0 では、v0.8.0 から非推奨にしていた v0.6 の名前を削除しました。

| 削除したもの | 代わりに使うもの |
|---|---|
| `list_mock_presets`、`activate_mock`、`deactivate_mock` | `list_presets`、`activate_preset`、`deactivate_preset` |
| `status` の `active_mock_presets`、`active_mock_presets_error` | `active_presets`、`active_presets_error` |
| `capture_stats` の `mock_presets` | `presets` |

各ツールのフィールドについては次のとおりです。

- 入力：`run` が示すツール一覧の入力スキーマにあるフィールドです。マイナーリリースで増える新しい入力は、省略できるものだけです。メジャーバージョンの間、入力を削除したり、必須にしたり、意味を変えたりはしません。
- 出力：`run` が示すツール一覧の出力スキーマにあるフィールドと、`status` と `capture_stats`（スキーマで中身を決めていないもの）については下に挙げたフィールドです。新しいフィールドはマイナーリリースで増えることがあるので、エージェントは知らないフィールドを無視してください。メジャーバージョンの間、フィールドを削除したり意味を変えたりはしません。
- 次の値は意味を変えません。`status` の `mode`（`tailnet`、`lan`）、`capture_stats` の `state`（`starting`、`ready`、`restarting`、`failed`）、プリセットの `kind`（`mock`、`map_remote`、`modify_headers`、`resolve`）、マーカーの `source`（`cli`、`mcp`。v1.3 から `console` も）、`list_passthrough` の接続の `reason`（`pass_hosts`、`raw_tcp`）。マイナーリリースで値が増えること（新しいモードなど）はあります。
- 人が読む文を入れるフィールド（`next_steps`、`note`、`msg`、`list_rules` と `explain_rules` の `rules_error` や、`active_presets_error` などのエラーのフィールド）はなくなりませんが、文面は変わりえます。

#### `status` と `reqcove status --json`

`reqcove status --json` は `status` ツールの JSON を出力します。答える `run` がないとき（動いていないとき、起動中か終了中のとき）は、標準出力に何も出さず、理由を標準エラーに出して、終了コード 1 で終わります。フィールドは次のとおりです。

- `mode`、`next_steps`、`allow_hosts`、`pass_hosts`、`service`、`capture`（`capture_stats` のフィールド。下記）、`active_presets`、`active_presets_error`。`active_presets` の各要素は `name`、`kind`、`description`、`target`、`header`、`host`、`address`、`method`、`url`、`operation`、`status`、`delay_ms`、`fault`、`active`、`remaining`、`expires_at` を持ちます（`list_presets` のプリセットと同じ）。
- v1.1 から、動かしたままホストを変えたとき（`reqcove capture`、`reqcove reload`）のフィールド：`scope_pending`（mitmproxy がまだ受け取りを返していない変更。人が読むための文で、ないときはフィールドもありません）、`scope_changed_at`（RFC 3339）、`scope_change`（`capture add api.example.com` や `reload` のようなコマンド）。後の 2 つは、最初の変更まではありません。`allow_hosts` と `pass_hosts` は、mitmproxy が受け取りを返したホストです。
- v1.1 から、`recording`：`on` か `stopped`（`reqcove capture stop` から `capture start` まで。値は今後増えることがあります）。止めている間、`allow_hosts` は `[]` で、`pass_hosts` はありません（何も記録しません）。`base_allow_hosts` と `base_pass_hosts` は、記録しているときに記録するホストです（ないときはフィールドもありません）。止めている間は、`start` で記録するホストです。v1.1 より前の `run` にはありません。
- v1.1 から、`recording` は `allow-all` にもなります（`reqcove capture allow-all --for D` から、終わるまで）。その間 `allow_hosts` は `["*"]`、`pass_hosts` は復号せずに通したままのホスト、`base_allow_hosts` は終わったあとに記録するホストです。`allow_all_until`（RFC 3339）と `allow_all_left`（`29m10s` のような Go の duration）が終わる時刻を伝えます。オフのときはありません。`records_outside_scope` は、残っている記録のうち、ホストが `base_allow_hosts` の外にあるものの数です（allow-all の間の記録で、終わったあとも残るもの、またはあとで外したホストのもの）。ないときはフィールドもありません。
- v1.1 から、`run` 自身について：`version`（`reqcove version` が表示するもの。`serverInfo` のものと同じ）、`manager`（起動したもの：`terminal`、`reqcove service install` の LaunchAgent かユニットなら `reqcove service`、`brew services`。値は増えることがあります。見分けられないときはありません）、`restart_command`（サービスの下で再起動するコマンド。`brew services restart reqcove` など。そのサービスが `run` と別のバイナリや、もうないバイナリを動かすときは `reqcove service install`。ターミナルから起動したときはありません）。さらにこのコンピュータでだけ（`--mcp-http` ではなし）、`config_file`（読んだ `--config` のファイル、フルパス。フラグだけのときはありません）、`config_unused`（引数なしの `run` が見つけて読まなかった、もう 1 つの設定ファイル）、`hosts_files`（`--allow-hosts=@FILE` と `--pass-hosts=@FILE` が読んだファイル）。v1.1 より古い `run` にはありません。そのとき `reqcove status` はバージョンを `serverInfo` から取ります。
- v1.2 から、このコンピュータでだけ（`--mcp-http` ではなし）：`executable`（`run` のバイナリ。シンボリックリンクはたどった先）と、macOS では `keep_awake`（`always`、`ac`、`never`）。v1.2 より古い `run` にはありません。
- v1.3 から、このコンピュータでだけ（`--mcp-http` ではなし）：`mitmweb`（`run` が mitmweb を動かしている間は true。`--web`）と `mitmweb_this_start_only`（再起動がこの起動だけオンにしたときは true。`reqcove restart --web`）。false のときはありません。リンクやパスワードは入れません。
- v1.2 から、このコンピュータでだけ（`--mcp-http` ではなし）：`capture_requests`。ユーザーを待っているエージェントの頼みです（それぞれ `get_capture_request` が返すもので、`note` はなし）。ないときはフィールドもありません。
- v1.1 から、このコンピュータだけで（`--mcp-http` では返しません）、ホストの発見（`reqcove capture discover`）について：オンの間の `discover_until`（RFC 3339）と `discover_left`。`out_of_scope_hosts`（各要素に `host`、`count`、それを記録するコマンドの `add`。`add` は普通のホスト名でないときはありません。多い順に最大 30 件）と、残している名前の数の `out_of_scope_hosts_kept`。ないときはフィールドもありません。`summarize` も同じ `out_of_scope_hosts` を返します。フィルターでは絞りません。
- `node`：`backend`、`node`、`ips`、`exit_node_approved`、`tailnet_lock`、`tailnet_lock_signed`、`node_key`、`devices`、`device_os`、`device_problems`、`health`。`backend` の値と `health` の文は Reqcove ではなく Tailscale のものなので、変わらないとは約束しません。
- `lan`（LAN モードのときだけ）：`interface`、`network`、`listen`、`stopped`、`allowed`（各要素に `addr` と `allowed_at`）、`refused`、`refused_more`。

確認状況：答える `run` がないときに標準出力に何も出さず、理由を標準エラーに出して終了コード 1 で終わることは、単体テストで確かめました。v1.1 のフィールドと、v1.0.0 の `run` の答えを新しい `reqcove status` が読むことも、単体テストで確かめました。

#### `capture_stats`

ドキュメントにあるフィールドは、`flows`、`flows_with_truncated_bodies`、`evicted`、`checkpoint`、`oldest_flow`、`newest_flow`、`max_flows`、`max_bytes`、`state`、`started`、`redacting`、`out_of_scope`、`passed_through`、`raw_tcp`、`raw_tcp_hosts`、`refused_hosts`、`pass_hosts`、`mitmproxy`、`python`（それぞれのバージョン）、`presets`、`retries`（v1.1 から。mitmproxy を続けて起動し直した回数）、`last_failure`（v1.1 から。最後に失敗した理由で、人が読むための文。失敗していなければ ""）、`next_attempt`（v1.1 から。次に試すのを待っている間だけ）、`rules_loaded`（ルールファイルを一度読み込んだあと）、`recording`（v1.1 から。`status` と同じく `on`、`stopped`、`allow-all` のどれか。止めている間 `pass_hosts` は空です）、マスクが有効なあいだの `mask_names` と `mask_values`（名前ごと、パターン番号ごとの一致数）です。それ以外は[変わりえます](#変わりうるもの)。

### ルールファイル（`--rules`）

最上位のキーは `mock`、`map_remote`、`map_local`、`modify_headers`、`resolve`（それぞれリスト）と `keep_host_header`（`true` か `false`）です。ほかのキーは拒否します。

- `map_remote`、`map_local`、`modify_headers`：1 つのルールを 1 つの文字列で、mitmproxy 自身の書式で書き、mitmproxy のコードが読みます。Reqcove はロックに書く mitmproxy を更新し続けます（[下記](#変わりうるもの)）。こうしたルールの読み方が変わる更新はメジャーリリースまで待ちます（セキュリティ修正は例外）。
- `mock`（Reqcove 独自）：マッピングのリストで、キーは `match`（`url`。`method` と `operation` は省略可）、`status`、`headers`、`body` か `body_file`、`delay_ms`、`fault`（`close`。このとき `status`、`headers`、`body`、`body_file` は書かない）、`preset`、`description`（`preset` があるとき）です。
- `resolve`（Reqcove 独自）：1 つのルールを 1 つの文字列で、`HOST=IPV4` または `HOST=IPV4:PORT`。
- `keep_host_header`（Reqcove 独自）：`map_remote` がアプリの `Host` を残します。
- `map_remote`、`modify_headers`、`resolve` のプリセット：マッピング `{rule, preset, description}` で書きます。`rule` は上の書式のルールの文字列、`preset` はその名前（マッピングでは必須）、`description` は省略できます。`map_local` はプリセットにできません。`modify_headers` のプリセットが変えるのはリクエストだけです（`~s` は不可）。
- プリセットの名前は英字、数字、`.`、`_`、`-` で 64 文字まで、説明は 1 行で 200 文字までです。

v1.0.0 で読み込めるファイルは、v1 のどのリリースでも読み込め、同じように働きます（セキュリティ修正は例外）。マイナーリリースでキーや種類が増えることがあり、それを使うファイルは古いバージョンでは読み込めません。

### CLI

コマンドとフラグは次のとおりです。各コマンドのフラグ定義から取りました。

| コマンド | フラグ |
|---|---|
| `reqcove run` | `--device`、`--allow-hosts`、`--pass-hosts`、`--rules`、`--rules-reload`、`--proto`、`--upstream-proxy`、`--upstream-ca`、`--local-proxy`、`--proxy-port`、`--lan`、`--lan-interface`、`--ui`、`--web`、`--mcp-http`、`--dns`、`--no-redact`、`--mask-names`、`--mask-values`、`--state`、`--hostname`、`--verbose`、`--config`、`--keep-awake`（v1.2） |
| `reqcove status` | `--json`、`--state` |
| `reqcove har` | `--host`、`--device`、`--since`、`--until`、`--status`、`--method`、`--user-agent`、`--limit`、`--state`（HAR 1.2 のファイルを標準出力へ） |
| `reqcove links` | `--state` |
| `reqcove lan allow ADDR`、`lan deny ADDR`、`lan list` | `--state` |
| `reqcove mark [TEXT]`（`-` で始まる文は `-- TEXT`） | `--state` |
| `reqcove capture add HOST…`、`capture remove HOST…`（v1.1 から） | `--pass`、`--state` |
| `reqcove capture set`（v1.1 から） | `--allow-hosts`、`--pass-hosts`、`--state` |
| `reqcove capture stop`、`capture start`（v1.1 から） | `--state` |
| `reqcove capture save`（v1.1 から） | `--state` |
| `reqcove capture allow-all`（v1.1 から） | `--for D`（最長 `24h`）か `--end`、`--state` |
| `reqcove capture discover`（v1.1 から） | `--for D`（最長 `24h`）か `--end`、`--state` |
| `reqcove capture requests`、`capture approve ID`、`capture deny ID`（v1.2 から） | `--state` |
| `reqcove console`（v1.2 から） | `--end`、`--tailnet`、`--print`（v1.3 から）、`--state` |
| `reqcove reload`（v1.1 から） | `--state` |
| `reqcove restart`（v1.3 から） | `--web`、`--state` |
| `reqcove mock add` | `--rules`、`--url`、`--method`、`--operation`、`--status`、`--header`、`--body`、`--body-file`、`--delay-ms`、`--fault`、`--preset`、`--description`、`--print`、`--state` |
| `reqcove setup` | なし |
| `reqcove service install` | `--config`、`--state` |
| `reqcove service restart`、`service uninstall` | なし |
| `reqcove init` | `--client NAME`（`claude`、`agents`、`codex`、`cursor`、`gemini`、`copilot`、`devin`）、`--print`、`--uninstall` |
| `reqcove cleanup` | `--delete-state`、`--hostname`、`--state` |
| `reqcove mcp` | `--state` |
| `reqcove version` | なし |

`--uvx`、`--python`、`--mitmproxy-spec` は変わりうるので、この一覧に入れていません（[下記](#変わりうるもの)）。

`reqcove console`（v1.2 から）は、`ctl.sock` の新しい op `console` で `run` に頼みます。v1.2 より古い `run` はこれに使い方の説明で答え、`reqcove console` は `run` を v1.2 以降で起動し直すよう伝えます（v1.1 の答えを使う単体テストで確認）。ページのリンク（`http://127.0.0.1:PORT/#c=CODE`）と表示する内容、ページから `run` への要求は変わりうるものです（[下記](#変わりうるもの)）。v1.3 から、`run` の `console` への答えは、ページを開く状態ディレクトリのファイルも示します（`file`。v1.2 の `reqcove console` はこれを使わず、これまでどおりリンクを引数にして開きます。v1.2 の `run` に対する v1.3 の `reqcove console` は何も開かず、リンクを表示します）。`reqcove console --end` は、もう 1 つの新しい op `console-end` で頼みます。v1.2 の `run` はこれに使い方の説明で（LAN モードでは LAN モードの拒否で）答え、`reqcove console --end` は `run` を v1.3 以降で起動し直すよう伝えます（どちらの答えも単体テストで確認）。`reqcove console --tailnet` は、`console` に新しいフィールド `tailnet: true` を付けて頼みます。v1.3 の `run` は、tailnet のページのアドレス（`addr`、`100.x.y.z:PORT`）で答え、`port` も `file` も返しません。v1.2 の `run` はこのフィールドを読まず、127.0.0.1 にページを開きます。答えに `addr` がないので、`reqcove console --tailnet` は `run` を v1.3 以降で起動し直すよう伝え、何も表示せず、何も開きません（単体テストで確認）。tailnet のページのアドレス、ポート、リンクは、このコンピュータのページと同じく変わりうるものです（[下記](#変わりうるもの)）。

`reqcove restart`（v1.3 から）は、`ctl.sock` の新しい op `restart` で `run` に頼みます（ほかのフィールドは `web` だけで、`reqcove restart --web` のとき true です。次の起動だけ mitmweb を動かします。LAN モードでも使えます）。`run` は `ok` と答え、答えを送ってから再起動を始めるか、何も止めずに拒否します。v1.2 以前の `run` はこれに使い方の説明で（LAN モードでは LAN モードの拒否で）答え、`reqcove restart` は `run` を止めて起動し直すよう伝えます（どちらの答えも単体テストで確認）。再起動が新しいプロセスに渡す変数 `REQCOVE_RESTART_*`、状態ディレクトリに置く config の写し（`restart-*.config`）、`config.failed`、`reqcove status` が読む `restart-note` は変わりうるものです（[下記](#変わりうるもの)）。v1.3 の `run` は止まる前に、exec するバイナリを `run --check-config` と自分の引数で実行します（隠れたモードで、`run -h` には出ず、変わりうるものです。再起動のためだけのものです）。終了コードは 0 か、理由とともに 1 です。そのモードのないバイナリは使い方の説明で答え（知らないフラグとして）、再起動は `run` だけで確かめ、そう伝えます（単体テストで確認）。

`reqcove capture save`（v1.3 から）は、ホストのファイルを指していない config では、`run` から、するはずの変更（人が読むテキスト）と新しいフィールド `confirm`（トークン）を受け取ります。y と答えると、そのトークンを `confirm` に入れてもう一度 `save` を送り、`run` は示した変更だけを書きます（そのあいだに config やホストのファイルが変わっていれば拒否します）。v1.3 より古い `capture save` はトークンを送り返さないので、何も書きません（コードから判断したものです）。トークンとテキストは変わりうるものです。

### `--config` のファイル

- `run` のフラグを 1 行に 1 つ書き、コマンドラインのフラグより先に読みます。1 回だけ指定するフラグはコマンドラインのものが使われ、繰り返せるフラグ（`--device`、`--allow-hosts`）は足し合わされます。空行と `#` で始まる行は読み飛ばします。語はスペースで区切り、シェルと同じように `'…'` か `"…"`（中では `\"` と `\\`）でまとめます。`~/` で始まる語はホームディレクトリからのパスとして読みます。
- 書けないもの：`--no-redact`、`--web`、`--rules-reload`、`--lan`、`--config`、そしてどう書いても（`@FILE` でも）`--allow-hosts '*'`。
- ファイルは通常のファイルで、自分が所有し、グループとほかの人に権限がない（`chmod 600`）ものでなければなりません。
- 置き場所：`reqcove service install`（その `--config` の既定値）と Homebrew なしの `reqcove setup` は `~/.config/reqcove/config`。Homebrew では `reqcove setup` が `$(brew --prefix)/etc/reqcove/config` に書き、`brew services` がそれを読みます。
- v1.1 から、引数をまったく付けない `reqcove run`（以前は断っていました）は、`--config FILE` と同じように `~/.config/reqcove/config` を読みます。なければ Homebrew のもの（その `reqcove` が Homebrew のものであるとき）を読みます。どちらもなければ、これまでどおり `--device` を求めます。引数を 1 つでも付けた `run` は、v1.0 と同じく、`--config` で指定したときだけファイルを読みます。`--config` を付けない `reqcove service install` も同じファイルを使います（インストール済みなら、入っているサービスの `--config`）。
- v1.1 から、`reqcove setup` はホストを、その隣の別のファイル `hosts`（`~/.config/reqcove/hosts` か `$(brew --prefix)/etc/reqcove/hosts`）に書きます。1 行に 1 つのホストで、`#` から後はコメントです。config には、そのファイルを読む `--allow-hosts=@FILE` の行を書きます。`reqcove capture save` が書き換えるのもこのファイルです。それより前に書いた config（`--allow-hosts` の行にホストがあるもの）は、これまでどおり読みます。
- v1.3 から、ホストのないホストのファイル（`--allow-hosts=@FILE`、`--pass-hosts=@FILE`。コメントだけか空のもの）を受け付け、ホストを足しません（以前は「has no hosts」で拒否しました）。`--mask-names` や `--mask-values` の `@FILE` は、行がなければこれまでどおり拒否します。記録するホストが必要なもの（`--pass-hosts` のホスト、`--rules`、`--upstream-proxy`）は、フラグがあるかではなく、実際のホストで確かめます。そのため、空のファイルの `--pass-hosts=@FILE` は、`--allow-hosts` がなくても受け付けます（以前は拒否しました）。
- v1.3 から、`reqcove capture save` は、ホストのファイルを指定していない config（`--allow-hosts=@FILE` や `--pass-hosts=@FILE` がないもの）に、y/N を聞いたうえで 1 行を最後に足し、そのファイルを隣に作ることがあります。前の config は `config.prev` として残します。ほかの行は変えません。
- v1.3 から、`reqcove setup` は `--allow-hosts=@FILE` の行と、config の隣のホストのファイルを必ず書きます。ホストを答えなかったときは、コメントだけのファイルを書き、ホストは足しません（以前は、`--allow-hosts` の行をコメントにして、ファイルは作りませんでした）。書く config とホストのファイルを、次の起動と同じように読んで確かめ、その起動が拒否するなら何も書きません。このコンピュータの Tailscale CLI が答えれば、タグのない自分のデバイスを一覧にし、番号で選べます（名前を打つこともできます）。

### 状態ディレクトリ

既定は `~/.reqcove` で、`--state DIR` で変えられます。利用者が触るファイルは次のとおりです。

- `mitmproxy/mitmproxy-ca-cert.pem`：CA の証明書。このコンピュータやブラウザに信頼させるときに使います（[ガイド](guide.ja.md#ios-シミュレーターを記録する--local-proxy)）。
- `mitmproxy/` 全体と、その中の `mitmproxy/mitmproxy-ca.pem`（CA の秘密鍵と証明書）：別のコンピュータと同じ CA を使うときにコピーします（[ガイド](guide.ja.md#2-台のコンピュータで同じ-ca-を使う)）。
- `lan-allowed`：LAN モードが中継するアドレス。`reqcove lan` で変えてください。
- `mcp-token` と `ui-token`：`--mcp-http` と `--ui` のトークン。エージェントやブラウザに渡すときに読み、作り直すときに消します（[ガイド](guide.ja.md)）。
- `ca-copies`（`~/.reqcove` だけ）：その CA をコピーした状態ディレクトリの一覧。`reqcove cleanup` が名前を挙げます。

ほかのファイル（`mcp.sock`、`tsnet/`、ログ、pid やプロキシ設定のファイル）は Reqcove 内部のもので、どのリリースでも変わりえます。

### Skill

`reqcove init` は Skill を `~/.claude/skills/reqcove`（Claude Code）と `~/.agents/skills/reqcove`（Codex、Cursor、Gemini CLI、Copilot CLI、Devin）に、または `--client` で指定したところだけに書きます。この置き場所と `init` のフラグは変わりません。Skill の文はバージョンごとに変わるので、アップデートしたら `reqcove init` をもう一度実行してください（入っている Skill が別のバージョンのものなら `reqcove status` がそう伝えます）。

## 変わりうるもの

次のものはパッチリリースも含め、どのリリースでも変わりえます。

- ログの行：`run`、サービス、mitmproxy のもの。
- `run` が出す準備完了の表示：文面とレイアウト。
- コマンドとツールのエラーや拒否の文、ツールの説明、サーバーの instructions（非推奨のツールの説明の先頭の「Deprecated」だけは残します）。
- `reqcove status` の文（`--json` は変わりません）。
- Reqcove が動かす mitmproxy と Python のロック（`internal/capture/mitm.py.lock`）：セキュリティ修正のため、どのリリースでも更新します。どのリリースがどのバージョンの mitmproxy を動かすかは約束しません。
- `--uvx`、`--python`、`--mitmproxy-spec`（`run` のもの。`--uvx` は `status` と `mock add` のものも）とその既定値：mitmproxy をどう動かすか（uv、Python、mitmproxy のバージョン）を選ぶもので、mitmproxy と uv に従います。
- 上に挙げていない `capture_stats` のフィールド：`held_bytes`、`restarts`、`state_detail`、`tls_failures`、`passed_through_open`、`addon_dropped_bodies`、`addon_dropped_events`、`bad_lines`、`masking_failed`、`unknown_version`、`orphan_updates`、`all_hosts`、`brotli`、`brotli_decode`、`zstd_decode`、`rules`、`rules_error`、`resolve`、`upstream`。マイナーリリースで変わったりなくなったりします。
- `reqcove console` のページ：ポート、レイアウト、`/api/` の要求とその答え（v1.3 の `/api/change`、`/api/save`、`/api/settings`、`/api/restart`、`/api/presets`、`/api/preset`、`/api/marker`、`/api/ca`、`/api/har` も）。tailnet のページ（`reqcove console --tailnet`）も同じです（ポート、そのうちどれを出すか、`status` の `console_sessions`）。
- `run --check-config`：再起動が、exec するバイナリに頼む隠れた確認のモード。
- `reqcove restart` が新しいプロセスに渡すもの（`REQCOVE_RESTART_*` の変数、fd）と、状態ディレクトリと config の隣に残すファイル（`restart-*.config`、`restart-note`、`config.failed`）。
- `poc/` フォルダ：メンテナーのメモで、リポジトリには入っていません。
- そのほか、このページで変わらないとしていないもの。

## `reqcove mcp` と別のバージョンの `run`

- MCP サーバーは、エージェントがつないだときに自分のバージョンを伝えます（`serverInfo`：名前は `reqcove`、バージョンは `reqcove version` が出すもの）。ソケット、`reqcove mcp`、`--mcp-http` のどれでも同じです。
- `reqcove mcp` が示すのは、つなぐ先の `run` ではなく自分のバージョンのツールで、出力スキーマは付けません。別のバージョンの `run` の答えがスキーマで拒否されないようにするためです。
- `run` のバージョンが `reqcove mcp` と違うと、つないで最初の答えに注記が付きます。注記は両方を同じバージョンにすることと、新しいほうで `reqcove run` を起動し直し、エージェントの MCP サーバーをつなぎ直すことを伝えます。
- この `reqcove mcp` にあって `run` にないツールのうち、プリセット、ルール、マーカーのツールは、動いている reqcove のそのバージョンにはそのツールがない、と答えます。それ以外のツールには、知らないツールだという `run` 自身のエラーがそのまま返ります。v1.2 より古い `run` に対する `request_capture_add` と `get_capture_request` は、その `run` には頼みの仕組みがないので v1.2 以降で起動し直すよう答えます（単体テストで確認）。
- これらの注記のほかに、バージョンの混在はサポートしません。`reqcove run` と `reqcove mcp` は同じバージョンで動かしてください。v1.0.0 の `reqcove mcp` には、古い `run` につないでも `list_mock_presets`、`activate_mock`、`deactivate_mock` はありません。これらを `run` や `reqcove mcp` で呼ぶと、代わりのツールの名前を書いたエラーが返ります。v1.0.0 の `reqcove status` は、古い `run` の `active_mock_presets` と `mock_presets` も読みます。v0.6 や v0.7 の `reqcove status` は古い名前しか読まないので、v1.0.0 の `run` につなぐと、有効なプリセットを表示しません（コードから判断したもの）。そのバージョンの `reqcove mcp` は、`run` の答えをそのまま渡します。

確認状況：テストで確かめたのは、出力スキーマを付けないツールの一覧、バージョンが違うときの注記、`run` にないツールへの 2 通りの答え、削除したツールを呼んだときのエラー、v1.0.0 の `reqcove status` が古い `run` のフィールドを読むことです。
