class Voidb < Formula
  desc "Terminal database manager replicating Navicat's core functionality with vim-style keys"
  homepage "https://github.com/limmytian/voidb"
  version "0.3.3"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/limmytian/voidb/releases/download/v0.3.3/voidb-0.3.3-darwin-arm64.tar.gz"
      sha256 "fee1ae96c5a6e4aa778a13013469387da095a07aa4d1412c1e17cad48b548008"
    else
      url "https://github.com/limmytian/voidb/releases/download/v0.3.3/voidb-0.3.3-darwin-x64.tar.gz"
      sha256 "87bf458b34f01ee2e9a0800c2be05a6b479424f479ede56b814c9cc661d33526"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/limmytian/voidb/releases/download/v0.3.3/voidb-0.3.3-linux-arm64.tar.gz"
      sha256 "f650fc7f6e0fc981418e34a69ee872e8cc5fc94e3dbbb76071ea81105d612c9e"
    else
      url "https://github.com/limmytian/voidb/releases/download/v0.3.3/voidb-0.3.3-linux-x64.tar.gz"
      sha256 "3d186454b9b35776971f9e8b2a6ea32db366eb8ee79f27c1a2cb6e24202f47d1"
    end
  end

  def install
    bin.install "voidb"
    bin.install "voidb-cli"
    if Dir.exist?("plugins")
      (pkgshare/"plugins").install Dir["plugins/*"]
    end
  end

  def caveats
    <<~EOS
      VoidB v#{version} installed successfully!

      Quick start:
        voidb                             # Launch interactive TUI
        voidb-cli plugin install-default  # Ensure all core database plugins are ready
        voidb-cli --help                  # Explore CLI & plugin commands

      In VoidB TUI, press 'p' to open the visual Plugin Marketplace.
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
