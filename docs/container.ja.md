# コンテナで Reqcove を動かす

[English](container.md)

Reqcove は、コンテナでも動きます（Docker。Podman でも同じコマンドで動くはずです）。uv、Python、mitmproxy、CA の秘密鍵はコンテナの中に閉じ、コンテナと volume を消せば片付きます。環境ごとにコンテナを 1 つ起動すれば、1 台のマシンで、それぞれ閉じた Exit Node をいくつも動かせます。

向いているのは Linux です。macOS では、コンテナは VM（Docker Desktop、OrbStack、colima）の中で動きます。シミュレーターと `--local-proxy` は使えず、Mac をスリープさせないようにしておく必要があります。Mac で複数の Exit Node を動かすなら、Mac の上で `--state` ごとに `run` を動かす形（[複数の Exit Node](several-exit-nodes.ja.md)）の方が、それらも使えます。

**確かめたこと**：`scripts/container-smoke.sh` を OrbStack（macOS、arm64）と CI（Linux、amd64 と arm64）で流しました。イメージができること、ネットワークなしで mitmproxy と mitmweb がイメージの中身だけで起動すること、新しい volume の状態のフォルダがコンテナのユーザーの持ち物で 0700 になること、別のコンテナの `reqcove mcp` が volume を通して `run` に届くこと、`docker exec … reqcove status` が答えること、同じ volume で 2 つ目の `run` を起動すると断られること、`docker stop` で正しく止まることです。手で（OrbStack で）確かめたこと：コンテナから tailnet にログインすること（Tailnet Lock の署名、Exit Node の承認）、iPhone の通信をそのコンテナに通すこと（コンテナの CA を入れ、GitHub アプリの通信が記録された）、`docker run -i` の `reqcove mcp` が MCP のクライアントに答えること、`docker exec … reqcove har`、`--mcp-http` を Grok Bot から読むこと、`docker run -i` で Claude Code（`claude -p`）が `status` を読むこと。**まだ試していないこと**：Linux のホストでの手の確認、Podman。

## 1. イメージを作る

イメージは公開していないので、リポジトリから作ります。

```sh
docker build -t reqcove .
```

distroless（シェルもパッケージ管理もない）のイメージで、root ではない専用のユーザー（65532）で動きます。

## 2. 起動する：名前を 1 つ決める

名前は 1 つ決めて、4 か所に使います。コンテナ、その volume、コンテナのホスト名（CA の名前になります）、ノードの名前です。

```sh
NAME=reqcove-staging
docker run -d --init --name $NAME --hostname $NAME \
  -v $NAME:/home/nonroot/.reqcove reqcove \
  run --device iphone --allow-hosts api.staging.example.com --hostname $NAME --ui
docker logs -f $NAME
```

- ログには、残っている手順が出ます。ログイン用の URL とリンクは出ません。`docker exec -it $NAME reqcove links` で、QR コード付きで表示できます（コンテナではまだ試していません）。`-t`（ターミナル）を付けると、`run` はホストと同じようにログにも表示し、`docker logs` に残ります。Exit Node の承認は、ホストで動かすときと同じく 1 回です。
- `--init` は、終わった mitmproxy のプロセスを片付けます。
- volume は名前付きのもの（`-v 名前:…`）だけを使ってください。Mac のフォルダをそのままつなぐと、ロックとソケットが VM の境を越えません。
- volume ごとに CA を作ります。iPhone には、コンテナごとにプロファイルを入れます。

## 3. エージェント

```sh
claude mcp add $NAME -- docker run -i --rm --network none --log-driver none --volumes-from $NAME reqcove mcp
```

エージェントのセッションごとにコンテナを 1 つ起動し、volume を通して `run` のソケットにつなぎます（確かめのスクリプトと、Claude Code の `claude -p` で確かめました）。`--volumes-from` は、run のコンテナがなければすぐに失敗します。`--log-driver none` は、ツールの答えを Docker のログに残さないためです。

`docker exec $NAME reqcove status` と `reqcove har` は、ホストと同じように使えます。

ほかの自分の端末のエージェント（Grok Bot）には、`run` に `--mcp-http` を付けます。ノードはコンテナの中にあるので、ポートを開ける必要はありません。URL とトークンは `docker exec -it $NAME reqcove links` で表示できます（[手順](guide.ja.md#ほかのデバイスのエージェントから使う--mcp-http)。`docker logs` に出ていたころに Grok Bot で試しました。コンテナでの `reqcove links` はまだ試していません）。

記録の時刻は、コンテナのタイムゾーン（既定は UTC）で付きます。

## コンテナで違うこと

- `--local-proxy`、シミュレーター、このコンピュータで CA を信頼することは、コンテナではできません。
- macOS：Mac がスリープすると VM が止まります。使う間は `caffeinate -i` を動かしておいてください。
- `-t` を付けなければ、`docker logs` にログイン用の URL とトークンは残りません。付けると、コンテナを消すまで残ります。トークンは、volume の中のファイルを消すまで有効です。`--log-opt max-size=10m` でログの大きさを抑えられます。
- `--rules` と `--upstream-proxy` の `localhost` は、コンテナ自身を指します。ホストは、Docker Desktop と OrbStack では `host.docker.internal` です（試していません）。`--rules` はフォルダをつないで渡します（`-v ./rules:/rules:ro` として `--rules /rules/x.yaml`）。`--proto` も同じです。
- `run` が表示するコマンド（`claude mcp add … reqcove mcp`、`reqcove status`）は、ホスト向けの形です。上の形に読み替えてください。
- VM のネットワーク越しでは、tailnet の通信が中継（DERP）になりやすいかもしれません。速さは測っていません。

## 複数の環境

2 を、別の名前（と別のフラグ）で繰り返します。それぞれが、自分のノード、CA、記録、エージェントの登録を持ちます。

## 片付け

```sh
docker rm -f $NAME && docker volume rm $NAME   # CA の鍵とログも一緒に消えます
```

そのあと、Tailscale の管理画面でマシンを削除し、iPhone から CA のプロファイルを削除します。
