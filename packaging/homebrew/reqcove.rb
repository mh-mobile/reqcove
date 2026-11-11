# Formula for a tap (mh-mobile/homebrew-tap). It builds from source, so the Go
# modules, the Tailscale fork included, are fetched during the build. Fill in
# url and sha256 for each release tag.
class Reqcove < Formula
  desc "Hand an iPhone's HTTP(S) traffic to an AI agent, over a Tailscale exit node"
  homepage "https://github.com/mh-mobile/reqcove"
  url "https://github.com/mh-mobile/reqcove/archive/refs/tags/v0.3.0.tar.gz"
  sha256 "e02c5fb0797ff7213ef9d0fbe64956a1ce5b1fc3e93eced1d836c6a1d7dc5459"
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
    EOS
  end

  test do
    assert_match "reqcove v#{version}", shell_output("#{bin}/reqcove version")
    assert_match "reqcove is not running", shell_output("#{bin}/reqcove status --state #{testpath}/state")
  end
end
