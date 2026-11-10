# 別の Mac から Reqcove の Exit Node を使う

[English](another-mac.md)

別の Mac（サブ機の MacBook など）も、iPhone と同じように Reqcove の Exit Node を使えます。`--allow-hosts` のホストへの HTTP(S) が記録され、その Mac の iOS シミュレーターの通信も記録されます。macOS 27 の VM で確かめました（Tailscale のアプリ、Reqcove の CA を指定した `curl`）。下のキーチェーンで CA を信頼させる手順と、その Mac のシミュレーターは、まだ試していません。

その Mac では、Tailscale のアプリ（App Store 版か、Tailscale の配布しているもの）を使ってください。Homebrew のオープンソース版の `tailscaled` では、Exit Node を選ぶと選ばれた表示になりますが、macOS が自分の既定の経路を使い続けるため、通信は Reqcove を通らずに直接出ます（同じ VM で見ました）。

## 1. Reqcove を動かしている Mac で、その Mac を `--device` で指定する

```sh
reqcove run --device iphone --device macbook-sub --allow-hosts api.example.com --ui
```

`macbook-sub` は、その Mac の tailnet でのマシン名です（`tailscale status` で一覧できます）。Reqcove は、`--device` の端末の通信しか運びません。

## 2. 別の Mac で、Exit Node を選ぶ

- メニューバーの Tailscale のアイコン › Exit Node › `reqcove` を選ぶ。または、
- `tailscale set --exit-node=reqcove` を実行する。

Exit Node をオンにすると、その Mac の通信は家の LAN 宛ても Reqcove に向かい、Reqcove は LAN 宛てを断ります。そのため、その Mac から家の LAN の機器（NAS など）に届かなくなります。届くようにするには、`--exit-node-allow-lan-access=true` も付けます。LAN 宛ての通信は Reqcove を通らずに直接届き、記録はされません。

## 3. HTTPS の中身も見るなら、その Mac に Reqcove の CA を信頼させる

Exit Node をオンにした状態で、その Mac の Safari で `http://mitm.it` を開き（`http://` まで自分で入力してください）、macOS 用の証明書を取ります。または、Reqcove を動かしている Mac から `~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem` を持ってきます。そのうえで、次を実行します。

```sh
security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db mitmproxy-ca-cert.pem
```

HTTPS だけを、そのユーザーだけが信頼する形になります。macOS がパスワードを聞いてきます。その Mac の iOS シミュレーターにも入れるなら、`xcrun simctl keychain booted add-root-cert mitmproxy-ca-cert.pem` も実行してください。

## 気をつけること

- その Mac の通信は、すべて Reqcove（と、それを動かしている Mac）を通ります。復号して記録するのは、`--allow-hosts` のホストだけです。
- その Mac が CA を信頼すると、Reqcove を動かしている Mac にある CA の秘密鍵で、その Mac に対してもあらゆる HTTPS のサイトになりすませるようになります。使い終わったら、信頼を外してください。
- 記録には、iPhone と同じく、その Mac のマシン名が付きます。

## 元に戻す

- Exit Node：Tailscale のメニュー › Exit Node › なし、または `tailscale set --exit-node=` を実行する。
- CA：キーチェーンアクセスで `Reqcove CA (…)` を削除する（信頼の設定も一緒に消えます）。または、`reqcove status` が出す指紋（SHA-256）を使って、`security delete-certificate -t -Z <SHA-256> ~/Library/Keychains/login.keychain-db` を実行する。
