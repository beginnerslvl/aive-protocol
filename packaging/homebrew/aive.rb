# Homebrew formula template for AIVE.
#
# AIVE has zero runtime dependencies, so the formula only needs Homebrew's
# bundled Python plus a virtualenv install. Publish it via a personal tap:
#
#   brew tap waleedsworld/aive
#   brew install waleedsworld/aive/aive
#
# To finalize for a real release, cut a git tag (e.g. v0.2.0), then fill in the
# archive URL below and its checksum:
#
#   curl -L https://github.com/waleedsworld/aive-protocol/archive/refs/tags/v0.2.0.tar.gz | shasum -a 256
#
class Aive < Formula
  include Language::Python::Virtualenv

  desc "AI-Validated Exploit: exploit-to-patch automation for GitHub repositories"
  homepage "https://github.com/waleedsworld/aive-protocol"
  url "https://github.com/waleedsworld/aive-protocol/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "REPLACE_WITH_TARBALL_SHA256"
  license "MIT"
  head "https://github.com/waleedsworld/aive-protocol.git", branch: "main"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "aive 0.2.0", shell_output("#{bin}/aive --version")
    # A scan of an empty dir should succeed and emit the v1 schema.
    (testpath/"empty").mkpath
    assert_match "aive.scan.v1", shell_output("#{bin}/aive scan #{testpath}/empty")
  end
end
