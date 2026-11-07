# 外出先の iPhone の通信を、自宅の Exit Node で見る

iPhone の通信を Tailscale の Exit Node に通して、その Exit Node で mitmproxy が HTTPS を復号します。iPhone が 5G でも Wi‑Fi でも、tailnet 内のブラウザから記録を見られます。iPhone 自身の Safari からも見られます。RoamRun の機能ではなく、Tailscale と mitmproxy だけで組む手順です。

この手順は 2026-11-06〜07 に、次の組み合わせで試しました。

- Exit Node：Ubuntu 24.04（aarch64、Mac 上の tart の VM）、Tailscale 1.104.1、mitmproxy 12.3.1
- iPhone：iOS 27.3、Tailscale アプリ

## 何が見えて、何が見えないか

試したときの結果は次のとおりです。

- 見えたもの：CA を信頼したあとのアプリと Safari の HTTP(S)。X の画像と動画、Slack、Discord、GitHub、Google、LINE の API などです。
- 見えないもの：証明書ピンニングを使うアプリの通信。X の API、povo、Duolingo、1Password は、mitmproxy の証明書を受けずに接続を切りました。
- 記録しないもの：Apple のホスト。Apple は、HTTPS を傍受する接続を失敗させると文書（https://support.apple.com/en-us/101555 ）に書いています。この手順では Apple 宛てを復号せず、そのまま通します。App Store と iCloud 写真は、この状態で動きました。App Store の表示は遅く感じましたが、理由は確かめていません。
- QUIC（UDP 443）は Apple 宛て以外を拒否し、アプリを TCP に戻します。IPv6 の転送も止めます。

通信は自宅を経由するので、送信元の IP は自宅の回線になり、応答時間も変わります。

## 用意するもの

- tailnet に入った Linux のマシン（ここでは「Exit Node」と呼びます）。iptables と systemd があること。
- Tailnet Lock を使っている tailnet では、そのマシンが署名済みであること。
- Tailscale の管理画面で、Exit Node を承認できること。
- iPhone に Tailscale アプリ。

## 1. Exit Node を用意する

Exit Node で、次を root で実行します。

```sh
printf "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n" > /etc/sysctl.d/99-tailscale.conf
sysctl -p /etc/sysctl.d/99-tailscale.conf
tailscale set --advertise-exit-node
```

管理画面（https://login.tailscale.com/admin/machines ）で、そのマシンの「…」から「Edit route settings」を開き、「Use as exit node」をオンにします。

## 2. DNS を確かめる

Exit Node を使う iPhone は、名前の解決も Exit Node に任せます。Exit Node で解決できない名前は、iPhone でも開けません。

```sh
resolvectl query example.com
```

試したときは、tart の DNS と Tailscale の DNS のどちらでも、example.com が SERVFAIL になりました。そのため、Exit Node の DNS を公開のものに変えました（`enp0s1` は Exit Node の LAN のインターフェース名）。

```sh
tailscale set --accept-dns=false
resolvectl dns enp0s1 1.1.1.1 8.8.8.8
```

## 3. mitmproxy を入れる

Exit Node の普通のユーザー（ここでは `admin`）で入れます。

```sh
python3 -m venv ~/mitm          # Ubuntu では先に apt install python3-venv
~/mitm/bin/pip install mitmproxy
```

Apple のホストを外す表を `~/ignore.txt` に置きます。1行が1つの正規表現です。mitmproxy は、接続先の `host:port`、TLS の SNI、HTTP の Host ヘッダーをこれに照らします。

```
(^|\.)(apple\.com|icloud\.com|icloud\.com\.cn|icloud-content\.com|cdn-apple\.com|mzstatic\.com|apple-cloudkit\.com|apple-livephotoskit\.com|apple-mapkit\.com|apple-dns\.net|apzones\.com|itunes\.com|apple|digicert\.com|digicert\.cn)(:\d+)?$
(^|\.)(apple-relay\.cloudflare\.com|apple-relay\.fastly-edge\.com|cp4\.cloudflare\.com)(:\d+)?$
^17\.\d+\.\d+\.\d+:
```

## 4. 通信を mitmproxy に回して、mitmweb を起動する

次のスクリプトを `~/mitm-up.sh` として置き、root で実行します。iptables の規則と mitmweb は Exit Node を再起動すると消えるので、そのたびに実行します。`USER_NAME` と `PASSWORD` は自分のものに変えます。

```sh
#!/bin/sh
USER_NAME=admin
PASSWORD=change-me
HOME_DIR=/home/$USER_NAME
TS_IP=$(tailscale ip -4)

# tailnet から来る TCP 80/443 を mitmproxy へ。Apple（17/8）と tailnet 宛ては回さない
iptables -t nat -N rr-mitm 2>/dev/null || iptables -t nat -F rr-mitm
iptables -t nat -A rr-mitm -d 17.0.0.0/8 -j RETURN
iptables -t nat -A rr-mitm -d 100.64.0.0/10 -j RETURN
iptables -t nat -A rr-mitm -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 8080
iptables -t nat -C PREROUTING -i tailscale0 -j rr-mitm 2>/dev/null || iptables -t nat -A PREROUTING -i tailscale0 -j rr-mitm
# QUIC は Apple 宛て以外を拒否して TCP に戻す。IPv6 の転送は止める
iptables -C FORWARD -i tailscale0 -p udp --dport 443 ! -d 17.0.0.0/8 -j REJECT 2>/dev/null || iptables -I FORWARD 1 -i tailscale0 -p udp --dport 443 ! -d 17.0.0.0/8 -j REJECT
ip6tables -C FORWARD -i tailscale0 -j REJECT 2>/dev/null || ip6tables -I FORWARD 1 -i tailscale0 -j REJECT

args=""; while read -r r; do args="$args --ignore-hosts $r"; done < $HOME_DIR/ignore.txt
systemctl stop mitmweb 2>/dev/null; systemctl reset-failed mitmweb 2>/dev/null
systemd-run --unit=mitmweb --uid=$USER_NAME --setenv=HOME=$HOME_DIR --setenv=PYTHONUNBUFFERED=1 \
  $HOME_DIR/mitm/bin/mitmweb --mode transparent --listen-port 8080 \
  --web-host $TS_IP --web-port 8081 --set web_open_browser=false --set web_password=$PASSWORD \
  --set block_global=false --set stream_large_bodies=1 --set store_streamed_bodies=true $args
```

オプションの意味は次のとおりです。

- `--web-host $TS_IP`：記録の画面を tailnet のアドレスだけで開きます。
- `block_global=false`：mitmproxy が外のアドレスからの接続を断らないようにします。tailnet の 100.x は外のアドレスではありませんが、念のため付けています。
- `stream_large_bodies=1`：本文を最後まで待たずに流します。これがないと、LINE の新着を受ける接続（終わらない HTTP/2 の要求）が相手に届かず、LINE は約16秒ごとに取り消してつなぎ直しました。新着も届きませんでした。
- `store_streamed_bodies=true`：流した本文も記録に残します。

## 5. iPhone を設定する

1. Tailscale アプリで、Exit Node にこのマシンを選びます。
2. Safari で http://mitm.it を開き、「iOS」の「Get mitmproxy-ca-cert.pem」からプロファイルをダウンロードします。
3. 「設定 › 一般 › VPN とデバイス管理」で、プロファイルをインストールします。
4. 「設定 › 一般 › 情報 › 証明書信頼設定」で、mitmproxy をオンにします。

## 6. 記録を見る

tailnet 内のブラウザで `http://<Exit Node の tailnet のアドレス>:8081/?token=<PASSWORD>` を開きます。iPhone 自身の Safari からも開けました。tailnet 宛ての通信は mitmproxy に回さないので、この画面を見る通信は記録に混ざりません。mitmweb を起動し直すと、それまでの記録は消えます。

## 7. 片付ける

iPhone で、次の2つを行います。

1. Tailscale アプリで Exit Node をオフにします。
2. 「設定 › 一般 › VPN とデバイス管理」で、mitmproxy のプロファイルを削除します。

この CA の秘密鍵は、Exit Node の `~/.mitmproxy/` にあります。プロファイルを残すと、この鍵を持つ人は、その iPhone に対してどのサイトにもなりすませます。

Exit Node では、root で次を実行します。

```sh
systemctl stop mitmweb
iptables -t nat -D PREROUTING -i tailscale0 -j rr-mitm
iptables -t nat -F rr-mitm && iptables -t nat -X rr-mitm
iptables -D FORWARD -i tailscale0 -p udp --dport 443 ! -d 17.0.0.0/8 -j REJECT
ip6tables -D FORWARD -i tailscale0 -j REJECT
tailscale set --advertise-exit-node=false
```

4 と 7 のスクリプトは、この VM で実行して確かめました。7 の最後の行（Exit Node の広告をやめる）だけは、まだ実行していません。
