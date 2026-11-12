# Formula for a tap (mh-mobile/homebrew-tap). It builds from source, so the Go
# modules, the Tailscale fork included, are fetched during the build. Fill in
# url and sha256 for each release tag.
class Reqcove < Formula
  desc "Hand an iPhone's HTTP(S) traffic to an AI agent, over a Tailscale exit node"
  homepage "https://github.com/mh-mobile/reqcove"
  url "https://github.com/mh-mobile/reqcove/archive/refs/tags/v0.4.0.tar.gz"
  sha256 "355fdf2ed8b08f6347236ada2f6ed36677c29fbc1a1faac4f5e8fd2109ceee6e"
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
