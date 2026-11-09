# 1 台のコンピュータで複数の Exit Node を動かす

[English](several-exit-nodes.md)

1 台のコンピュータで、Reqcove の Exit Node をいくつも同時に動かせます。それぞれに別の設定（`--allow-hosts`、`--rules`、`--ui` など）を持たせ、iPhone の Tailscale アプリで切り替えます。状態のフォルダ 1 つにつき、`reqcove run` を 1 つ動かします。v0.1.0 のあとに追加しました。iPhone で切り替えて使うところは、まだ試していません。以下は、テスト（名前、ポート、CA）と、Exit Node の仕組みから考えたことです。

## 1. それぞれ別の `--state` で起動する

```sh
reqcove run --device iphone --allow-hosts api.example.com --ui
reqcove run --device iphone --allow-hosts api.staging.example.com --rules staging.yaml --ui --state ~/.reqcove-staging
```

それぞれ別のターミナルで動かします。1 つめは `~/.reqcove` を使い、名前は今までどおり `reqcove` です。

- **名前**：`--state` のフォルダの名前が `reqcove-名前` なら（先頭のドットは除きます）、ノードの名前は `reqcove-名前` になります。この例では `reqcove-staging` です。ほかの名前のフォルダでは `reqcove` のままで、2 つめは Tailscale が `reqcove-1` に変えます。名前を決めたいときは `--hostname` を付けてください。前に別の名前で使ったフォルダでは、新しい名前に変わります（Tailscale がマシンの名前を変えます）。前の名前のままにしたいときは、`--hostname reqcove` を付けます。
- **ログインと承認は、ノードごとに 1 回**：初めてのときと同じです（足りないことは `reqcove status --state ~/.reqcove-staging` で分かります）。tailnet のポリシーに `autoApprovers` を書いておけば、承認は自動になります（README の Tips）。
- **CA**：新しい状態のフォルダでは、初めての起動で `~/.reqcove` の CA を写します（`run` がそう表示します）。そのため、iPhone にもう入っているプロファイルが、どのノードでも使えます。前に使ったフォルダでは、そのフォルダの CA をそのまま使います。`~/.reqcove` にまだ CA がないうちに起動したフォルダも、自分の CA を作ります。先に、デフォルトのノードを起動してください。

## 2. iPhone の Tailscale アプリで切り替える

Exit Node で `reqcove` か `reqcove-staging` を選びます。切り替えたあとにページが開かなくなったら、Exit Node をいったん切って、つなぎ直してください（reqcove を起動し直したあとと同じです）。

記録はノードごとに別です。エージェントに見えるのは、つないだノードの記録です。

## 3. エージェント：ノードごとに MCP サーバーを登録する

`run` は、そのノード用のコマンドを、状態のフォルダを付けて表示します。

```sh
claude mcp add reqcove -- reqcove mcp
claude mcp add reqcove-staging -- reqcove mcp --state /Users/you/.reqcove-staging
```

`reqcove status`、`reqcove har`、`reqcove cleanup` にも `--state` を付けられます。

## ポート

- `--ui` はそれぞれのノードの 80 番、`--web` はそれぞれのノードの 8081 番です。リンクにはノードのアドレスが入るので、それぞれのリンクで、そのノードのページが開きます。`--ui` のページには、ノードの名前が出ます（`reqcove` のときは出ません）。
- このコンピュータの中では、mitmweb は `127.0.0.1:8081` で待ち受けます。ほかの run が使っているときは、8091〜8099 のうち空いている最初のポートを使います（どれかは `run` が表示します）。ノードの側は 8081 のままなので、起動の順番で iPhone のリンクは変わりません。
- `--local-proxy` は、コンピュータ 1 台に 1 つだけです（ポート 8082 と、システムの Web プロキシの設定が 1 組しかないため）。2 つめの run で指定すると、何も変えずにすぐ止まります。

## 知っておくこと

- CA の秘密鍵は、それぞれの状態のフォルダ（中の `mitmproxy/`）に入ります。1 つを消しても（`reqcove cleanup --delete-state --state …`）、ほかのフォルダには残ります。iPhone からプロファイルを消すと、どのノードでも復号できなくなります（`~/.reqcove` と同じ CA を使うノードでは、`cleanup` がそう表示します）。
- ノードは、どれも Tailscale の管理画面に 1 台のマシンとして載ります。使わなくなったものは削除してください（名前は `reqcove cleanup --state …` が表示します）。
