class Voidb < Formula
  desc "Terminal database manager replicating Navicat's core functionality with vim-style keys"
  homepage "https://github.com/limmytian/voidb"
  version "0.3.5"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/limmytian/voidb/releases/download/v0.3.5/voidb-0.3.5-darwin-arm64.tar.gz"
      sha256 "49de4ceaeeb02920f728eb71eaf55ddc82c4773b7234dc2db93dc5240e478938"
    else
      url "https://github.com/limmytian/voidb/releases/download/v0.3.5/voidb-0.3.5-darwin-x64.tar.gz"
      sha256 "ae67690269cda8e1ba9ef95c2cef8a94c7f41130bb4b0bc18d21e8c005706f13"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/limmytian/voidb/releases/download/v0.3.5/voidb-0.3.5-linux-arm64.tar.gz"
      sha256 "f7caf9baec2cc6d3a606f007d28db3b073deedad8f3e6b030edce1226f2e7fb7"
    else
      url "https://github.com/limmytian/voidb/releases/download/v0.3.5/voidb-0.3.5-linux-x64.tar.gz"
      sha256 "db251a70d382d3c1799afec2cda7510bc8fe8977ad04ef8221bad76eeb1198ea"
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
