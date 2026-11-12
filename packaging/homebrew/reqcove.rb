# Formula for a tap (mh-mobile/homebrew-tap). It builds from source, so the Go
# modules, the Tailscale fork included, are fetched during the build. Fill in
# url and sha256 for each release tag.
class Reqcove < Formula
  desc "Hand an iPhone's HTTP(S) traffic to an AI agent, over a Tailscale exit node"
  homepage "https://github.com/mh-mobile/reqcove"
  url "https://github.com/mh-mobile/reqcove/archive/refs/tags/v0.5.0.tar.gz"
  sha256 "3c4816681f7d07e33a113037fa6f8af9ca5ad8609ee33139bfeaba5c7b8bacda"
  license "MIT"

  depends_on "go" => :build
  depends_on "uv" # reqcove runs mitmproxy with uv, from its lock

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w -X main.version=v#{version}"), "./cmd/reqcove"
  end

  def caveats
    <<~EOS
      The first `reqcove run` fetches mitmproxy and Python with uv.
      State, including a CA private key, lives in ~/.reqcove.

      To keep it running at login (`brew services start reqcove`), write run's
      flags, one a line, in #{etc}/reqcove/config (chmod 600), such as:
        --device iphone
        --allow-hosts api.example.com
      `reqcove links` prints the login URL; the log is #{var}/log/reqcove.log.
    EOS
  end

  # No keep_alive: a missing or refused config ends it once, not in a loop.
  service do
    run [opt_bin/"reqcove", "run", "--config", etc/"reqcove/config"]
    environment_variables PATH: std_service_path_env
    log_path var/"log/reqcove.log"
    error_log_path var/"log/reqcove.log"
  end

  test do
    assert_match "reqcove v#{version}", shell_output("#{bin}/reqcove version")
    assert_match "reqcove is not running", shell_output("#{bin}/reqcove status --state #{testpath}/state")
  end
end
