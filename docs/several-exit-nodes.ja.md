# 1 台のコンピュータで複数の Exit Node を動かす

[English](several-exit-nodes.md)

1 台のコンピュータで、Reqcove の Exit Node をいくつも同時に動かせます。それぞれに別の設定（`--allow-hosts`、`--rules`、`--ui` など）を持たせ、iPhone の Tailscale アプリで切り替えます。状態のフォルダ 1 つにつき、`reqcove run` を 1 つ動かします。v0.1.0 のあとに追加しました。iPhone で切り替えて使うところは、まだ試していません。以下は、テスト（名前、ポート、CA）と、Exit Node の仕組みから考えたことです。

## 1. それぞれ別の `--state` で起動する

```sh
reqcove run --device iphone --allow-hosts api.example.com --ui
reqcove run --device iphone --allow-hosts api.staging.example.com --rules staging.yaml --ui --state ~/.reqcove-staging
```

それぞれ別のターミナルで動かします。1 つめは `~/.reqcove` を使い、名前は今までどおり `reqcove` です。`--state ~/x` は、スペースを空けて書いてください。`--state=~/x` と書くと、シェルが `~` をそのまま渡すので、`run` は断ります。

- **名前**：新しい `--state` のフォルダの名前が `reqcove-名前` なら（先頭のドットは除きます）、ノードの名前は `reqcove-名前` になります。この例では `reqcove-staging` です。ほかの名前のフォルダでは `reqcove` になります。名前を決めたいときは `--hostname` を付けてください（2 つのノードが両方 `reqcove` だと、Tailscale が片方の名前を変えて区別します。Tailscale の説明によるもので、試していません）。名前は状態のフォルダ（`node-name`）に記録され、次の起動と `cleanup` はそれを使います。前の版の reqcove が使ったフォルダでは、`reqcove` のままです。
- **ログインと承認は、ノードごとに 1 回**：初めてのときと同じです（足りないことは `reqcove status --state ~/.reqcove-staging` で分かります）。tailnet のポリシーに `autoApprovers` を書いておけば、承認は自動になります（README の Tips）。
- **CA**：CA のない状態のフォルダでは、起動のときに `~/.reqcove` の CA を写します（どこに写したかを `run` が表示します）。そのため、iPhone にもう入っているプロファイルが、どのノードでも使えます。自分の CA があるフォルダでは、それをそのまま使います。`~/.reqcove` にまだ CA がなければ、そのノードは自分の CA を作ります（`run` がそう表示します）。先に、デフォルトのノードを起動してください。`~/.reqcove` の CA のファイルが欠けていれば、`run` はどれが欠けているかを示して止まります。

## 2. iPhone の Tailscale アプリで切り替える

Exit Node で `reqcove` か `reqcove-staging` を選びます。切り替えたあとにページが開かなくなったら、Exit Node をいったん切って、つなぎ直してください（reqcove を起動し直したあとと同じです）。

記録はノードごとに別です。エージェントに見えるのは、つないだノードの記録です。

## 3. エージェント：ノードごとに MCP サーバーを登録する

`run` は、そのノード用のコマンドを、状態のフォルダを付けて表示します。

```sh
claude mcp add reqcove -- reqcove mcp
claude mcp add reqcove-staging -- reqcove mcp --state /Users/you/.reqcove-staging
```

`reqcove status`、`reqcove har`、`reqcove cleanup` にも `--state` を付けられます。`run` と `status` がそのノードについて表示するコマンドには、`--state` が付いています。

## ポート

`--ui` は、それぞれのノードの 80 番です。mitmweb（`--web`）には、入り口が 2 つあります。

| | `reqcove`（先に起動） | `reqcove-staging`（あとに起動） |
|---|---|---|
| ノード：iPhone が開く所。`run` が出すリンクと QR コード | `http://100.1.1.1:8081/…` | `http://100.2.2.2:8081/…` |
| このコンピュータ：ここのブラウザで開く所 | `http://127.0.0.1:8081/…` | `http://127.0.0.1:8091/…` |

- ノードの側は、どのノードも 8081 番です。ノードごとにアドレスが違うのでぶつからず、起動の順番で iPhone のリンクは変わりません。
- このコンピュータの 127.0.0.1 は 1 つしかないので、最初の mitmweb が 8081 を使い、次からは 8091〜8099 のうち空いている最初のポートを使います（どれかは `run` が表示します）。ノードは、自分の 8081 をそこへ中継します。
- `--ui` のページには、ノードの名前が出ます（`reqcove` のときは出ません）。
- `--local-proxy` は、コンピュータ 1 台に 1 つだけです（ポート 8082 と、システムの Web プロキシの設定が 1 組しかないため）。2 つめの run で指定すると、何も変えずにすぐ止まります。

## 知っておくこと

- CA の秘密鍵は、それぞれの状態のフォルダ（中の `mitmproxy/`）に入ります。1 つを消しても（`reqcove cleanup --delete-state --state …`）、ほかのフォルダには残ります。`~/.reqcove` の `reqcove cleanup` は、写した先のフォルダを表示します（`~/.reqcove/ca-copies` に記録しています）。iPhone からプロファイルを消すと、どのノードでも復号できなくなります（CA を共有するノードの `cleanup` が、そう表示します）。
- ノードは、どれも Tailscale の管理画面に 1 台のマシンとして載ります。使わなくなったものは削除してください（`reqcove cleanup --state …` は、`run` が付けた名前を表示します。Tailscale が `reqcove-1` などに変えたものは、管理画面ではその名前で出ます）。
