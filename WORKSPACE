workspace(name = "electronx")

# Load bazel_skylib for common utilities
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# OpenSSL (using rules_foreign_cc for building C/C++ dependencies)
http_archive(
    name = "rules_foreign_cc",
    sha256 = "2a4d07cd64b0719b39a7c12218a3e507672b82a97b98c6a89d38565894cf7c51",
    strip_prefix = "rules_foreign_cc-0.9.0",
    url = "https://github.com/bazelbuild/rules_foreign_cc/archive/refs/tags/0.9.0.tar.gz",
)

load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")

rules_foreign_cc_dependencies()
