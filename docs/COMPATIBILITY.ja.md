# 互換性

[English](COMPATIBILITY.md) · [README](../README.ja.md)

**v1.0.0 から適用します。** それより前（v0.x）は、ここに書いたことでもマイナーリリースで変わることがあり、実際に変わったものもあります。

メジャーバージョンの間は変わらないもの、どのリリースでも変わりうるもの、変更の知らせ方を書きます。一覧は記憶ではなくコード（MCP サーバーが登録するツール、各コマンドのフラグ、ルールファイルの読み込み処理）から取りました。テストで確かめた点はそう書いています。それ以外はコードを読んで書いたものです。

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

## メジャーバージョンの間は変わらないもの

メジャーバージョンの間、ここに挙げたものは削除せず、意味も変えません。マイナーリリースで増えることはあります。

### MCP ツール

このコンピュータから（`reqcove mcp` と `run` のソケット）使えるのは次の 19 個です。

`status`、`list_flows`、`wait_for_flows`、`search_flows`、`summarize`、`get_flow`、`list_ws_messages`、`diff_flows`、`list_devices`、`list_tls_failures`、`list_passthrough`、`capture_stats`、`list_presets`、`activate_preset`、`deactivate_preset`、`list_rules`、`explain_rules`、`add_marker`、`list_markers`

`--mcp-http` から使えるのは最初の 12 個（`status` から `capture_stats` まで）で、プリセット、ルール、マーカーのツールは使えません。`--mcp-http` の `status` には `active_presets` と `active_presets_error` がありません。

v1.0.0 で削除したもの（v0.8.0 から非推奨。v0.6 の名前）：

| 削除したもの | 代わりに使うもの |
|---|---|
| `list_mock_presets`、`activate_mock`、`deactivate_mock` | `list_presets`、`activate_preset`、`deactivate_preset` |
| `status` の `active_mock_presets`、`active_mock_presets_error` | `active_presets`、`active_presets_error` |
| `capture_stats` の `mock_presets` | `presets` |

各ツールのフィールド：

- 入力：`run` が示すツール一覧の入力スキーマにあるフィールドです。新しい入力は、省略できるものとしてだけマイナーリリースで増えます。メジャーバージョンの間、入力を削除したり、必須にしたり、意味を変えたりはしません。
- 出力：`run` が示すツール一覧の出力スキーマにあるフィールドと、`status` と `capture_stats`（スキーマで中身を決めていないもの）については下に挙げたフィールドです。新しいフィールドはマイナーリリースで増えることがあるので、エージェントは知らないフィールドを無視してください。メジャーバージョンの間、フィールドを削除したり意味を変えたりはしません。
- 次の値は意味を変えません。`status` の `mode`（`tailnet`、`lan`）、`capture_stats` の `state`（`starting`、`ready`、`restarting`、`failed`）、プリセットの `kind`（`mock`、`map_remote`、`modify_headers`、`resolve`）、マーカーの `source`（`cli`、`mcp`）。マイナーリリースで値が増えること（新しいモードなど）はあります。
- 人が読む文を入れるフィールド（`next_steps`、`note`、`msg`、`rules_error` や `active_presets_error` などのエラーのフィールド）はなくなりませんが、文面は変わりえます。

#### `status` と `reqcove status --json`

`reqcove status --json` は `status` ツールの JSON を出力します。答える `run` がないとき（動いていないとき、起動中か終了中のとき）は、標準出力に何も出さず、理由を標準エラーに出して、終了コード 1 で終わります（ユニットテスト）。そのフィールド：

- `mode`、`next_steps`、`allow_hosts`、`pass_hosts`、`service`、`capture`（`capture_stats` のフィールド。下記）、`active_presets`、`active_presets_error`。`active_presets` の各要素は `name`、`kind`、`description`、`target`、`header`、`host`、`address`、`method`、`url`、`operation`、`status`、`delay_ms`、`fault`、`active`、`remaining`、`expires_at` を持ちます（`list_presets` のプリセットと同じ）。
- `node`：`backend`、`auth_url`、`node`、`ips`、`exit_node_approved`、`tailnet_lock`、`tailnet_lock_signed`、`node_key`、`devices`、`device_os`、`device_problems`、`health`。`backend` の値と `health` の文は Reqcove ではなく Tailscale のもので、約束しません。
- `lan`（LAN モードのときだけ）：`interface`、`network`、`listen`、`stopped`、`allowed`（各要素に `addr` と `allowed_at`）、`refused`、`refused_more`。

#### `capture_stats`

ドキュメントにあるフィールド：`flows`、`flows_with_truncated_bodies`、`evicted`、`checkpoint`、`oldest_flow`、`newest_flow`、`max_flows`、`max_bytes`、`state`、`started`、`redacting`、`out_of_scope`、`passed_through`、`refused_hosts`、`pass_hosts`、`mitmproxy`、`python`（それぞれのバージョン）、`presets`、`rules_loaded`（ルールファイルを一度読み込んだあと）、マスクが有効なあいだの `mask_names` と `mask_values`（名前ごと、パターン番号ごとの一致数）。それ以外は[変わりえます](#変わりうるもの)。

### ルールファイル（`--rules`）

最上位のキーは `mock`、`map_remote`、`map_local`、`modify_headers`、`resolve`（それぞれリスト）と `keep_host_header`（`true` か `false`）です。ほかのキーは拒否します。

- `map_remote`、`map_local`、`modify_headers`：1 つのルールを 1 つの文字列で、mitmproxy 自身の書式で書き、mitmproxy のコードが読みます。Reqcove はロックする mitmproxy を更新し続けます（[下記](#変わりうるもの)）。こうしたルールの読み方が変わる更新はメジャーリリースまで待ちます（セキュリティ修正は例外）。
- `mock`（Reqcove 独自）：マッピングのリストで、キーは `match`（`url`。`method` と `operation` は省略可）、`status`、`headers`、`body` か `body_file`、`delay_ms`、`fault`（`close`。このとき `status`、`headers`、`body`、`body_file` は書かない）、`preset`、`description`（`preset` があるとき）です。
- `resolve`（Reqcove 独自）：1 つのルールを 1 つの文字列で、`HOST=IPV4` または `HOST=IPV4:PORT`。
- `keep_host_header`（Reqcove 独自）：`map_remote` がアプリの `Host` を残します。
- `map_remote`、`modify_headers`、`resolve` のプリセット：マッピング `{rule, preset, description}` で書きます。`rule` は上の書式のルールの文字列、`preset` はその名前（マッピングでは必須）、`description` は省略できます。`map_local` はプリセットにできません。`modify_headers` のプリセットが変えるのはリクエストだけです（`~s` は不可）。
- プリセットの名前は英字、数字、`.`、`_`、`-` で 64 文字まで、説明は 1 行で 200 文字までです。

v1.0.0 で読み込めるファイルは、v1 のどのリリースでも読み込め、同じように働きます（セキュリティ修正は例外）。マイナーリリースでキーや種類が増えることがあり、それを使うファイルは古いバージョンでは読み込めません。

### CLI

コマンドとフラグ（各コマンドのフラグ定義から）：

| コマンド | フラグ |
|---|---|
| `reqcove run` | `--device`、`--allow-hosts`、`--pass-hosts`、`--rules`、`--rules-reload`、`--proto`、`--upstream-proxy`、`--upstream-ca`、`--local-proxy`、`--proxy-port`、`--lan`、`--lan-interface`、`--ui`、`--web`、`--mcp-http`、`--dns`、`--no-redact`、`--mask-names`、`--mask-values`、`--state`、`--hostname`、`--verbose`、`--config`、`--uvx`、`--python`、`--mitmproxy-spec` |
| `reqcove status` | `--json`、`--state`、`--uvx` |
| `reqcove har` | `--host`、`--device`、`--since`、`--until`、`--status`、`--method`、`--user-agent`、`--limit`、`--state`（HAR 1.2 のファイルを標準出力へ） |
| `reqcove links` | `--state` |
| `reqcove lan allow ADDR`、`lan deny ADDR`、`lan list` | `--state` |
| `reqcove mark [TEXT]`（`-` で始まる文は `-- TEXT`） | `--state` |
| `reqcove mock add` | `--rules`、`--url`、`--method`、`--operation`、`--status`、`--header`、`--body`、`--body-file`、`--delay-ms`、`--fault`、`--preset`、`--description`、`--print`、`--state`、`--uvx` |
| `reqcove setup` | なし |
| `reqcove service install` | `--config`、`--state` |
| `reqcove service restart`、`service uninstall` | なし |
| `reqcove init` | `--client NAME`（`claude`、`agents`、`codex`、`cursor`、`gemini`、`copilot`、`devin`）、`--print`、`--uninstall` |
| `reqcove cleanup` | `--delete-state`、`--hostname`、`--state` |
| `reqcove mcp` | `--state` |
| `reqcove version` | なし |

`--mitmproxy-spec` と `--python` の既定値はロックに従うので、変わりえます（[下記](#変わりうるもの)）。

### `--config` のファイル

- `run` のフラグを 1 行に 1 つ書き、コマンドラインのフラグより先に読みます。1 回だけ指定するフラグはコマンドラインのものが使われ、繰り返せるフラグ（`--device`、`--allow-hosts`）は足し合わされます。空行と `#` で始まる行は読み飛ばします。語はスペースで区切り、シェルと同じように `'…'` か `"…"`（中では `\"` と `\\`）でまとめます。`~/` で始まる語はホームディレクトリから始まります。
- 書けないもの：`--no-redact`、`--web`、`--rules-reload`、`--lan`、`--config`、そしてどう書いても（`@FILE` でも）`--allow-hosts '*'`。
- ファイルは通常のファイルで、自分のものであり、グループとほかの人に権限がないこと（`chmod 600`）。
- 置き場所：`reqcove service install`（その `--config` の既定値）と Homebrew なしの `reqcove setup` は `~/.config/reqcove/config`。Homebrew では `reqcove setup` が `$(brew --prefix)/etc/reqcove/config` に書き、`brew services` がそれを読みます。

### 状態ディレクトリ

既定は `~/.reqcove` です（`--state DIR`）。利用者が触るファイル：

- `mitmproxy/mitmproxy-ca-cert.pem`：CA の証明書。このコンピュータやブラウザに信頼させるときに使います（[ガイド](guide.ja.md#ios-シミュレーターを記録する--local-proxy)）。
- `mitmproxy/` 全体と、その中の `mitmproxy/mitmproxy-ca.pem`（CA の秘密鍵と証明書）：別のコンピュータと同じ CA を使うときにコピーします（[ガイド](guide.ja.md#2-台のコンピュータで同じ-ca-を使う)）。
- `lan-allowed`：LAN モードが中継するアドレス。`reqcove lan` で変えてください。
- `ca-copies`（`~/.reqcove` だけ）：その CA をコピーした状態ディレクトリの一覧。`reqcove cleanup` が名前を挙げます。

ほかのファイル（`mcp.sock`、`tsnet/`、トークン、ログ、pid やプロキシ設定のファイル）は Reqcove 内部のもので、どのリリースでも変わりえます。

### Skill

`reqcove init` は Skill を `~/.claude/skills/reqcove`（Claude Code）と `~/.agents/skills/reqcove`（Codex、Cursor、Gemini CLI、Copilot CLI、Devin）に、または `--client` で指定したところだけに書きます。この置き場所と `init` のフラグは変わりません。Skill の文はバージョンごとに変わるので、アップデートしたら `reqcove init` をもう一度実行してください（入っている Skill が別のバージョンのものなら `reqcove status` がそう言います）。

## 変わりうるもの

次のものは、パッチリリースも含め、どのリリースでも変わりえます。

- ログの行：`run`、サービス、mitmproxy のもの。
- `run` が出す準備完了の表示：文面とレイアウト。
- コマンドとツールのエラーや拒否の文、ツールの説明、サーバーの instructions（非推奨のツールの説明の先頭の「Deprecated」だけは残します）。
- `reqcove status` の文（`--json` は変わりません）。
- Reqcove が動かす mitmproxy と Python のロック（`internal/capture/mitm.py.lock`）、それに従う `--mitmproxy-spec` と `--python` の既定値：セキュリティ修正のため、どのリリースでも更新します。
- 上に挙げていない `capture_stats` のフィールド：`held_bytes`、`restarts`、`state_detail`、`tls_failures`、`passed_through_open`、`addon_dropped_bodies`、`addon_dropped_events`、`bad_lines`、`masking_failed`、`unknown_version`、`orphan_updates`、`all_hosts`、`brotli`、`brotli_decode`、`zstd_decode`、`rules`、`rules_error`、`resolve`、`upstream`。マイナーリリースで変わったりなくなったりします。
- `poc/` フォルダ：メンテナーのメモで、リポジトリには入っていません。
- そのほか、このページで変わらないとしていないもの。

## `reqcove mcp` と別のバージョンの `run`

- MCP サーバーは、エージェントがつないだときに自分のバージョンを伝えます（`serverInfo`：名前は `reqcove`、バージョンは `reqcove version` が出すもの）。ソケット、`reqcove mcp`、`--mcp-http` のどれでも同じです。
- `reqcove mcp` が示すのは、つなぐ先の `run` ではなく自分のバージョンのツールで、出力スキーマは付けません。別のバージョンの `run` の答えがスキーマで拒否されないようにするためです（テスト）。
- `run` のバージョンが `reqcove mcp` と違うと、つないで最初の答えに注記が付きます。両方を同じバージョンにすること、新しいほうで `reqcove run` を起動し直し、エージェントの MCP サーバーをつなぎ直すことを伝えます（テスト）。
- この `reqcove mcp` にあって `run` にないツール：プリセット、ルール、マーカーのツールは、動いている reqcove（そのバージョン）にそのツールがないと答えます（テスト）。それ以外は `run` 自身のエラー（知らないツール）がそのまま返ります（テスト）。
- これらの注記のほかに、バージョンの混在はサポートしません。`reqcove run` と `reqcove mcp` は同じバージョンで動かしてください。v1.0.0 の `reqcove mcp` には、古い `run` につないでも `list_mock_presets`、`activate_mock`、`deactivate_mock` はありません。これらを `run` や `reqcove mcp` に呼ぶと、代わりのツールの名前を書いたエラーが返ります（テストで確認）。v1.0.0 の `reqcove status` は、古い `run` の `active_mock_presets` と `mock_presets` も読みます（テストで確認）。v0.6 や v0.7 の `reqcove status` と `reqcove mcp` は古い名前しか読まないので、v1.0.0 の `run` につなぐと、有効なプリセットを表示しません（コードを読んだだけです）。
