class Voidb < Formula
  desc "Terminal database manager replicating Navicat's core functionality with vim-style keys"
  homepage "https://github.com/limmytian/voidb"
  version "0.3.7"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/limmytian/voidb/releases/download/v0.3.7/voidb-0.3.7-darwin-arm64.tar.gz"
      sha256 "04c9baa1916404e091c839e60882dc27ee2bc66f5e1c6ae6d4a4f7ed22070ee2"
    else
      url "https://github.com/limmytian/voidb/releases/download/v0.3.7/voidb-0.3.7-darwin-x64.tar.gz"
      sha256 "6ca1673ae154386dba8ad31538fd848054b2775e9e2ca4de644716758a497ddb"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/limmytian/voidb/releases/download/v0.3.7/voidb-0.3.7-linux-arm64.tar.gz"
      sha256 "1caeb1ab9d0c2f0b643d0f20cb41b9d562da1e5611632fe7e82a5f966076c9ce"
    else
      url "https://github.com/limmytian/voidb/releases/download/v0.3.7/voidb-0.3.7-linux-x64.tar.gz"
      sha256 "90a665f287f86b0b010b8b4bae75f8c89ca34606486b59c68ee785ce32c7e2fc"
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
