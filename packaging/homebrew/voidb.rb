class Voidb < Formula
  desc "Terminal database manager replicating Navicat's core functionality with vim-style keys"
  homepage "https://github.com/limmytian/voidb"
  version "0.3.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/limmytian/voidb/releases/download/v0.3.0/voidb-0.3.0-darwin-arm64.tar.gz"
      sha256 "6cd53ccdc667b19b3b00bc77edfedb26f0c9751e9d0b0c69867f350504961495"
    else
      # Placeholder for Intel Mac binary if published
      url "https://github.com/limmytian/voidb/releases/download/v0.3.0/voidb-0.3.0-darwin-x64.tar.gz"
      sha256 ""
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/limmytian/voidb/releases/download/v0.3.0/voidb-0.3.0-linux-arm64.tar.gz"
      sha256 ""
    else
      url "https://github.com/limmytian/voidb/releases/download/v0.3.0/voidb-0.3.0-linux-x64.tar.gz"
      sha256 ""
    end
  end

  def install
    bin.install "voidb"
    bin.install "voidb-cli"
    bin.install "voidb-sync-server" if File.exist?("voidb-sync-server")
  end

  def caveats
    <<~EOS
      VoidB v#{version} installed successfully!

      Quick start:
        voidb                 # Launch interactive TUI
        voidb-cli --help      # Explore CLI & plugin commands

      In VoidB TUI, press 'p' to open the visual Plugin Marketplace.
      Install official plugins directly from CLI:
        voidb-cli plugin search
        voidb-cli plugin install mysql
        voidb-cli plugin install s3
        voidb-cli plugin install docker
    EOS
  end

  test do
    assert_match "voidb", shell_output("#{bin}/voidb-cli --version")
  end
end
