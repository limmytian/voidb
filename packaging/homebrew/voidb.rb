class Voidb < Formula
  desc "Terminal database manager replicating Navicat's core functionality with vim-style keys"
  homepage "https://github.com/limmytian/voidb"
  version "0.3.6"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/limmytian/voidb/releases/download/v0.3.6/voidb-0.3.6-darwin-arm64.tar.gz"
      sha256 "b0f6ded9874bd311b8e3e150dd624bbb2acc567e5903347df9b55870aaf7c6df"
    else
      url "https://github.com/limmytian/voidb/releases/download/v0.3.6/voidb-0.3.6-darwin-x64.tar.gz"
      sha256 "1280b28db13abf2f6d20dd8f7de66dcfd519aad6848bcbd01279fe7481d3a7c8"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/limmytian/voidb/releases/download/v0.3.6/voidb-0.3.6-linux-arm64.tar.gz"
      sha256 "31f3f85fb34a5ac4ce6b6c1d76babd2cccd7c339dc1418d1d555655b3b40621a"
    else
      url "https://github.com/limmytian/voidb/releases/download/v0.3.6/voidb-0.3.6-linux-x64.tar.gz"
      sha256 "88eb14bde4f24ac31c5720481bd50caa9a374f5315f3dfa214d07c35577bda1d"
    end
  end

  def install
    bin.install "voidb"
    bin.install "voidb-cli"
  end

  def caveats
    <<~EOS
      VoidB v#{version} installed successfully!

      Quick start:
        voidb                             # Launch interactive TUI
        voidb-cli plugin install-default  # Install the recommended plugins (optional)
        voidb-cli --help                  # Explore CLI & plugin commands

      Plugins are installed separately in your user plugin directory.
      Install official plugins directly from CLI:
        voidb-cli plugin search
        voidb-cli plugin install mysql
        voidb-cli plugin install s3
        voidb-cli plugin install docker
    EOS
  end

  test do
    assert_match "voidb #{version}", shell_output("#{bin}/voidb-cli --version")
  end
end
