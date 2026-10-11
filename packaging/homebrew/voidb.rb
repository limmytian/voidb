class Voidb < Formula
  desc "Terminal database manager replicating Navicat's core functionality with vim-style keys"
  homepage "https://github.com/limmytian/voidb"
  version "0.3.4"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/limmytian/voidb/releases/download/v0.3.4/voidb-0.3.4-darwin-arm64.tar.gz"
      sha256 "f1afa88551739bbd6b47e8278c6b64953cd42c1cbd6bcf4180a4408ad58c7750"
    else
      url "https://github.com/limmytian/voidb/releases/download/v0.3.4/voidb-0.3.4-darwin-x64.tar.gz"
      sha256 "8fd8ed7732b291ab2f0dffd030c1d52b8cb6f2e19d2978a4c96d5625924c7f49"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/limmytian/voidb/releases/download/v0.3.4/voidb-0.3.4-linux-arm64.tar.gz"
      sha256 "2c69da30e206a1004b652a25b9070813014dc89dfe5c15de538cea2b465207a9"
    else
      url "https://github.com/limmytian/voidb/releases/download/v0.3.4/voidb-0.3.4-linux-x64.tar.gz"
      sha256 "ac90b0167e7e12ef8f9b44eb4927dd6a03cc548d8094f7976570020761fdd666"
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
