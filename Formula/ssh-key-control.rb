class SshKeyControl < Formula
  desc "SSH Key Control: native macOS SSH signing approvals and security history"
  homepage "https://github.com/alvnukov/ssh-key-control"
  # First tagged release: replace `head` with
  #   url "https://github.com/alvnukov/ssh-key-control/archive/refs/tags/v1.0.0.tar.gz"
  #   sha256 "..."
  head "https://github.com/alvnukov/ssh-key-control.git", branch: "main"
  license "MIT"

  depends_on "go" => :build
  depends_on xcode: ["15.0", :build]
  depends_on macos: :ventura

  def install
    system "make", "install", "PREFIX=#{prefix}", "APPDIR=#{prefix}/Applications", "VERSION=#{version}", "SWIFTFLAGS=--disable-sandbox"
  end

  def caveats
    <<~EOS
      Register the agent for your user (without sudo):
        ssh-key-control install
      then quit and reopen your terminal. `ssh-key-control doctor` checks the result.

      To use the supervised menu bar app, copy it to /Applications or
      ~/Applications, open that copy, and choose Set Up SSH Agent:
        open "#{opt_prefix}/Applications"
    EOS
  end

  test do
    assert_match(/^ssh-key-control /, shell_output("#{bin}/ssh-key-control --version"))
    assert_match "usage:", shell_output("#{bin}/ssh-key-control 2>&1", 2)
  end
end
