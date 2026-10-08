class Voidb < Formula
  desc "Terminal database manager replicating Navicat's core functionality with vim-style keys"
  homepage "https://github.com/limmytian/voidb"
  version "0.3.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/limmytian/voidb/releases/download/v0.3.2/voidb-0.3.2-darwin-arm64.tar.gz"
      sha256 "00bf3dc7649785b93e51c97a56f12a490b402b4c3f632a388d0fa6e6854d8fb4"
    else
      # Placeholder for Intel Mac binary if published
      url "https://github.com/limmytian/voidb/releases/download/v0.3.2/voidb-0.3.2-darwin-x64.tar.gz"
      sha256 ""
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/limmytian/voidb/releases/download/v0.3.2/voidb-0.3.2-linux-arm64.tar.gz"
      sha256 "18d34681e2ba6d0c1546524bcb529d73796662b8a64d0e41dd77b5bfde4e0a14"
    else
      url "https://github.com/limmytian/voidb/releases/download/v0.3.2/voidb-0.3.2-linux-x64.tar.gz"
      sha256 "bb4cc3b5859da78542ec7573d300ee4a1ca1e571bea2da77749308320f7fdbd0"
    end
  end

  def install
    bin.install "voidb"
    bin.install "voidb-cli"
    bin.install "voidb-sync-server" if File.exist?("voidb-sync-server")
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
    assert_match "voidb", shell_output("#{bin}/voidb-cli --version")
  end
end
