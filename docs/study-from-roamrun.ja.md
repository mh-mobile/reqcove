# 検討メモ：外出先の iPhone の通信を自宅から見る

まだ何も作っていない。このメモは、何を確かめたかと、何が未確認かを分けて書く。

## やりたいこと

- 外出先の iPhone が 5G で通信している。
- 自宅の Mac か Linux で、その HTTP(S) のリクエストとレスポンスを見る。必要なら書き換える。
- iPhone の VPN は同時に1つしか使えない。そのため、Tailscale を使ったまま通す方法をとる。

## 案

### 案A：アプリだけをプロキシに向ける（Exit Node は使わない）

- Mac で mitmproxy を Tailscale のアドレスで待ち受けさせる。
- テストするアプリの Debug ビルドだけ、`URLSessionConfiguration.connectionProxyDictionary` に Mac の `100.x.x.x:8080` を入れる。
- Tailscale は 100.x 宛ての通信をセルラーでも運ぶので、5G でも届くはず（未確認）。
- 見えるのはそのアプリの通信だけになる。Apple のサービスはプロキシを通らないので、除外は要らない。

### 案B：Exit Node で端末全体を通し、透過プロキシで受ける

- Linux の Exit Node で、`tailscale0` から来る TCP 80/443 を iptables で REDIRECT する。行き先は mitmproxy の `--mode transparent`。UDP 443 は落とし、QUIC から TCP に戻させる（未確認）。
- tailnet には、もう Exit Node を出している Linux のノード（`nas`）がある。既存のノードなら、Tailnet Lock の署名を新しくする必要はない。ただし、人の NAS の iptables を触ることになるので、使う前に確認する。
- Mac だけで同じことができるかは分からない。Tailscale の Mac アプリが Exit Node として転送する通信を、pf か mitmproxy の `local` モードで曲げられるかを試していない。

## Apple のサービスの除外（案B で要る）

Apple の文書「Use Apple products on enterprise networks」（https://support.apple.com/en-us/101555 、2026-08-07 版）にはこうある。

- Apple のサービスは、HTTPS を傍受（SSL インスペクション）する接続をすべて失敗させる。Web プロキシを通すなら、文書が挙げるホストの傍受を止めるよう書いてある。
- 同じ文書が、ファイアウォール向けに IPv4 の `17.0.0.0/8` と IPv6 の `2403:300::/32`、`2620:149::/32`、`2a01:b740::/32` を挙げている。

除外は2段に分けられる。

1. IP で外す（iptables）。REDIRECT の前に `-d 17.0.0.0/8 -j RETURN` を置く。これで Apple 自身のアドレス宛ては mitmproxy に来ない。ただし、Apple の CDN や、Cloudflare・Fastly にある Apple のリレー（`apple-relay.cloudflare.com` など）は 17/8 の外にある。
2. 名前で外す（mitmproxy の `ignore_hosts`）。一致した接続は復号せず、そのまま中継する。

mitmproxy 12.3.1 の `ignore_hosts` で確かめたことは次のとおり。

- `addons/next_layer.py` の `_ignore_connection` は、接続先の `host:port` を正規表現で照らす（大文字小文字は区別しない）。TLS の ClientHello の SNI と HTTP の Host ヘッダーも、`host:port` の形にして照らす。そのため、透過モードで IP しか分からない接続でも、SNI で外せる。
- この Mac で通常のプロキシモードとして試した。`--ignore-hosts '(^|\.)apple\.com:'` を付けて `https://www.apple.com` を curl すると、200 が返った。証明書の発行者は Apple 自身（`Apple Public EV Server RSA CA 1 - G1`）のままだった。`https://example.com` は mitmproxy の証明書になり、curl はそれを信頼せず失敗した（期待どおり）。

Apple の文書が挙げるドメインから、正規表現の案を作った。

```
(^|\.)(apple\.com|icloud\.com|icloud\.com\.cn|icloud-content\.com|cdn-apple\.com|mzstatic\.com|apple-cloudkit\.com|apple-livephotoskit\.com|apple-mapkit\.com|apple-dns\.net|apzones\.com|itunes\.com|apple|digicert\.com|digicert\.cn)(:\d+)?$
(^|\.)(apple-relay\.cloudflare\.com|apple-relay\.fastly-edge\.com|cp4\.cloudflare\.com)(:\d+)?$
^17\.\d+\.\d+\.\d+:
```

- 3行目は SNI のない 17/8 宛ての接続を拾う。iptables で外せない場合の予備になる。

- この表を、Apple のホスト6件と、似た名前を含むほかのホスト5件（`notapple.com`、`apple.com.evil.net` など）に当てた。前者はすべて一致し、後者はどれも一致しなかった。
- `apple` は `token.safebrowsing.apple` などの `.apple` という TLD を指す。
- `ignore_hosts` に入れた名前の通信は記録に残らない。Apple 宛ての通信も見たい場合は、この表から外す必要がある。
- 未確認：TLS の Encrypted Client Hello（ECH）を使う通信では SNI が見えない。その場合、外せるのは 1 の IP で外す分だけになる。iOS が実際に ECH を使うかは確かめていない。
- Push（`*.push.apple.com` の 5223 など）は 80/443 以外のポートなので、REDIRECT しなければそもそも mitmproxy に来ない。

## 確かめていないこと

- 案A：5G の iPhone から、Tailscale 経由で Mac の mitmproxy に届くか。CA を入れた iPhone で、アプリの HTTPS が見えるか。
- 案B：Linux の Exit Node で REDIRECT が効くか。QUIC を落とすとアプリが TCP に戻るか。Apple を外したときに、iCloud や App Store、Push が普通に動くか。
- 案B を Mac だけでやれるか。
- 証明書ピンニングを使うアプリでどうなるか（復号できず、失敗するはず）。

## RoamRun に入れるなら（試したあとで決める）

- mitmproxy（MIT ライセンス）は同梱せず、ユーザーが入れたものを起動する。
- RoamRun の役目はつなぎ込み：待ち受けと Apple の除外表を用意し、CA を iPhone に入れる手段を渡すこと。
- 画面の操作もいっしょにするなら、外出先の端末へは tailnet 越しの `--at` でつなぐことになる。この経路は view ではサポート外（取りこぼしがひどい）。

## 案C：iPhone の独立アプリ（RoamRun の外の別プロジェクト）

iPhone 上で通信を取り、tailnet 内のブラウザから見る案。調べたことは次のとおり。

- Trace（https://github.com/Trace-iOS/Trace ）は MIT ライセンス。2026-11-06 時点でスターは18、最後の push は 2026-04-13。サブモジュールは quiche と hev-socks5-tunnel（MIT）。
- Trace の `Docs/explanation/capture-architecture.md` によると、取り方は2つある。1つは、システムのプロキシに自分の MITM プロキシを登録する方法。もう1つは、Network Extension のパケットトンネルで TUN を作り、hev-socks5-tunnel で SOCKS5 に変えて受ける方法。どちらも VPN の枠を使う構成と読める（未確認）。
- Tailscale の libtailscale（BSD-3-Clause）に、Swift の TailscaleKit がある。README によると、tailnet のノードとして listen と dial ができ、tailnet 内へ URLSession で要求も出せる。iOS 向けのフレームワークも作れる。

いちばんの論点は、iOS で同時に使える VPN が1つだけなこと。

- 取得用のトンネルを動かす間、Tailscale アプリは止まる。iPhone を tailnet につなぐのは、アプリに埋め込んだ TailscaleKit だけになる。
- そのため、取得中は RoamRun のような Tailscale アプリ頼みの機能が、その iPhone では使えなくなる。「後から組み合わせる」には、この点を解く必要がある。
- TailscaleKit のノードは tailnet の新しいノードになる。この tailnet は Tailnet Lock を使っているので、署名が一度要る。
- 未確認：Extension 内の TailscaleKit の通信が、自分のトンネルを通らずに外へ出るか。Go のランタイムと MITM エンジンを1つの Extension に入れたとき、メモリの上限に収まるか。

最初の試作（PoC）では、次の順に確かめるとよい。

1. パケットトンネルの Extension に TailscaleKit を入れ、Mac へ毎秒1行ずつ送る。ログを iPhone から押し出す向きにして、iPhone 側では待ち受けない。
2. 画面ロック中やバックグラウンドでも送り続けるか、メモリがどれだけかを実機で見る。
3. 通ったら、Trace のような取得（まず HTTP の一覧だけ）を足す。

## 案D：取得と tailnet を1つの VPN にまとめる iPhone アプリ

Charles の iOS アプリと同じく、ローカルの VPN で通信を取る。違いは、同じトンネルが tailnet への出入口も兼ねる点。VPN の枠は1つで足りるので、Tailscale アプリを止めても tailnet が切れない。

tsnet（tailscale/tailscale の `tsnet/tsnet.go`、2026-11-06 の main）で確かめたことは次のとおり。

- `Loopback()` は、tailnet へ出る SOCKS5 プロキシをループバックのアドレスに立てる（ユーザー名 `tsnet`、パスワードは返される proxyCred）。libtailscale の C の API にも `tailscale_loopback` がある。
- `RegisterFallbackTCPHandler` は、どのリスナーも受けない TCP の流れを受け取るコールバックを登録する。C の API には無いので、使うなら Go 側で包む。
- `Dial`、`Listen`、`ListenPacket`（UDP）もある。

そこで、次の組み立てが考えられる（どれも未確認）。

1. トンネルの TUN を、Trace と同じく hev-socks5-tunnel で SOCKS5 に変えて受ける。
2. 宛先が tailnet（`100.64.0.0/10`、`fd7a:115c:a1e0::/48`）なら、tsnet の SOCKS5 へ渡す。tailnet 内のアクセスは、取得の対象から外すか、別に記録する。
3. それ以外は、MITM するか、そのまま外へ出す。Apple のホストはそのまま出す。

難しいのは、tailnet からこの iPhone へ入ってくる通信。RoamRun は Mac から iPhone の tailnet のアドレスへつなぐので、ここが通らないと RoamRun と組み合わせられない。

- tsnet の側では、`RegisterFallbackTCPHandler` で任意のポートの TCP を受けられる。
- 受けた流れを、iPhone の中のサービスへ Extension から渡せるかが分からない。サービスがどのインターフェースで待っているかを確かめていない。RoamRun が使う通信に UDP があるかも、ここでは調べていない。
- 渡せない場合は、Tailscale のエンジンそのもの（TUN を持つ形）を tsnet の代わりに Extension へ入れる。Tailscale のクライアントを作り直すのに近く、重い。

PoC では、次の順に確かめるとよい。

1. 案C の 1 と 2（Extension 内の TailscaleKit、バックグラウンド、メモリ）。
2. Safari から tailnet 内の Mac の HTTP へ、このトンネル経由で届くか（外へ出る向き）。
3. Mac から iPhone の tailnet のアドレスへ、RoamRun の bridge がつながるか（入ってくる向き）。

## RoamRun が iPhone へ使う通信（コードと記録から）

案D の「入ってくる向き」に要るものを、RoamRun のコードとドキュメントから調べた。実機は使っていない。

- 外側の通信は、どれも Mac から iPhone の tailnet のアドレスへの TCP だった。
  - bridge の中継（`Sources/RoamRun/Bridge/Relays.swift`）は、`NWConnection` で TCP の接続だけを張る。
  - つなぐ先は2つ（`docs/how-it-works.md`）。1つはペアリングのポートで、見たところ 49152、空いていなければ続く番号。もう1つは、そのたびに変わるトンネルのポート N。
  - roamrunctl のデバイス操作も、49152〜49167 への TCP から始まる（`Rust/roamrunctl/src/device.rs` の `PORTS`）。
- 画面の映像と音は UDP で届く。ただし、その UDP は TCP のトンネルの中で動く。idevice のソフトウェアの TCP/IP の上に開くからだ（`Rust/RoamRunDevice/src/lib.rs` の `bind_udp`）。tailnet には UDP として出ない。
- 案D で通すべきなのは、任意のポートへの TCP が Mac から入ってくる向きになる。これは tsnet の `RegisterFallbackTCPHandler` で受けられる。

もっと大きな制約は iOS の側にある。README と roamrunctl の README によると、セルラーだけの iPhone は新しい接続を受けなかった（試した結果）。

- bridge を始めるには、iPhone が Wi‑Fi につながっている必要がある。Ready になったあと、「Keep debugging on cellular」が入っていれば、セルラーに移っても続く。
- release-checklist の 18 では、セルラーの間は `Connection refused` になっていた。
- そのため、5G だけの iPhone を RoamRun で新しくつなぐことは、案D と関係なくできない。Wi‑Fi（ポケットルーターや別の端末のテザリング）で始めてからセルラーに移る使い方なら、セッションは続く。

案D の分かれ目は、次のように絞れる。

- tsnet で受けた TCP を、Extension から iPhone 自身のサービス（49152 や N）へ渡せるか。Wi‑Fi がないと接続を断ることから、サービスはインターフェースごとに待っている、と推測する（未確認）。そうなら、ループバックや自分のアドレスへつなぎ直すやり方は通らない見込みが高い。
- 通らない場合は、Tailscale のエンジンを TUN ごと Extension に入れる。tailnet から来た IP パケットは、`packetFlow` へそのまま書く（Tailscale のアプリと同じ形）。

## 案B を試した結果（2026-11-06）

Linux の VM（`ubuntu-standin`、Ubuntu 24.04、tart）を Exit Node にした。mitmproxy 12.3.1 の mitmweb を透過モードで動かし、iPhone（`iphone-duo`、iOS 27.3）は 5G から Exit Node を使った。設定は上の案B のとおりで、加えて IPv6 の転送を止めた。

- CA を信頼したあと、mitmweb には復号できた HTTP(S) が702件出た。X の画像と動画、Slack、Discord、GitHub、Google、アプリの中の WebKit の通信などが見えた。
- mitmproxy の証明書を受けずに切った接続があった。X の API（`api.twitter.com` が142回、`api.x.com`）、`app.povo.jp`、Duolingo、1Password など。証明書ピンニングと見られる。
- UDP 443 を記録すると、出ていたのは Apple のアドレス（17.248.x.x）宛てだけだった。17/8 は拒否から外しているので、そのまま外へ出ている。
- Safari で example.com が開けなかった。原因は Exit Node 側の DNS だった。Exit Node を使う iPhone は名前の解決も Exit Node に任せる。この VM は tart の DNS（192.168.64.1）と 100.100.100.100 のどちらでも example.com が SERVFAIL になり、1.1.1.1 では解決できた。VM の DNS を 1.1.1.1 と 8.8.8.8 に変えたが、そのあと iPhone で開けるかを試す前に VM が止まった。
- 2026-11-07 に続きを試した。VM の DNS を変えたあとは、Safari で example.com が開け、mitmweb に `GET https://example.com/` が 200 で出た。このとき iPhone は自宅の Wi‑Fi から Exit Node を使っていた。
- App Store のページは開いた。表示は遅く感じたとのこと。Apple のホストへの通信は復号されず、失敗の記録もなかった。遅い理由は確かめていない。
- LINE で、MacBook から書いた Keep メモが Duo に出なかった。新着を受ける `POST /PUSH/1/subs`（legy-jp.line-apps.com、HTTP/2）に応答が返らず、LINE が約16秒ごとに取り消していた。mitmproxy は初期設定で本文を最後まで受けてから送る。そこで `--set stream_large_bodies=1 --set store_streamed_bodies=true` で本文を流すようにした。すると、この要求に 200 が返って接続が続き、Keep メモも Duo に出た。
- mitmweb の画面（VM の tailnet のアドレスの 8081）は、Exit Node を使っている同じ iPhone の Safari からも開けた。
- iCloud 写真は同期した。iPhone で撮ったスクリーンショットが、ほかの端末に出た。mitmproxy の記録に、iCloud のホストで失敗したものはなかった。
- 設定は VM の `/home/admin/mitm-up.sh` に入れた（iptables と mitmweb は再起動で消える）。
