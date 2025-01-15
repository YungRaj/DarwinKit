load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

FUZZTEST_COMMIT = "b86e98ff1149313e43333d1017c3a87baa6721c5"

http_archive(
    name = "com_google_fuzztest",
    strip_prefix = "fuzztest-" + FUZZTEST_COMMIT,
    url = "https://github.com/google/fuzztest/archive/" + FUZZTEST_COMMIT + ".zip",
)

http_archive(
    name = "com_google_googletest",
    strip_prefix = "googletest-1.15.2",
    url = "https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz",
)

################################################################################
# Transitive dependencies
################################################################################

# Required by com_google_fuzztest.
http_archive(
    name = "com_googlesource_code_re2",
    sha256 = "cd191a311b84fcf37310e5cd876845b4bf5aee76fdd755008eef3b6478ce07bb",
    strip_prefix = "re2-2024-02-01",
    url = "https://github.com/google/re2/releases/download/2024-02-01/re2-2024-02-01.tar.gz",
)

# Required by com_google_fuzztest.
http_archive(
    name = "com_google_absl",
    sha256 = "338420448b140f0dfd1a1ea3c3ce71b3bc172071f24f4d9a57d59b45037da440",
    strip_prefix = "abseil-cpp-20240116.0",
    url = "https://github.com/abseil/abseil-cpp/releases/download/20240116.0/abseil-cpp-20240116.0.tar.gz"
)

# Required by com_google_absl.
http_archive(
    name = "bazel_skylib",
    sha256 = "cd55a062e763b9349921f0f5db8c3933288dc8ba4f76dd9416aac68acee3cb94",
    urls = ["https://github.com/bazelbuild/bazel-skylib/releases/download/1.5.0/bazel-skylib-1.5.0.tar.gz"],
)

http_archive(
    name = "com_google_riegeli",
    strip_prefix = "riegeli-411cda7f6aa81f8b8591b04cf141b1decdcc928c",
    url = "https://github.com/google/riegeli/archive/411cda7f6aa81f8b8591b04cf141b1decdcc928c.tar.gz",
)

http_archive(
    name = "org_brotli",
    sha256 = "84a9a68ada813a59db94d83ea10c54155f1d34399baf377842ff3ab9b3b3256e",
    strip_prefix = "brotli-3914999fcc1fda92e750ef9190aa6db9bf7bdb07",
    urls = ["https://github.com/google/brotli/archive/3914999fcc1fda92e750ef9190aa6db9bf7bdb07.zip"],  # 2022-11-17
)

http_archive(
    name = "snappy",
    sha256 = "38b4aabf88eb480131ed45bfb89c19ca3e2a62daeb081bdf001cfb17ec4cd303",
    strip_prefix = "snappy-1.1.8",
    urls = ["https://github.com/google/snappy/archive/1.1.8.zip"],  # 2020-01-14
    build_file = "@com_google_riegeli//third_party:snappy.BUILD",
)

http_archive(
    name = "highwayhash",
    strip_prefix = "highwayhash-08d3f5b4d351d2202531ff22f2ba2e0e0e9865e7",
    urls = ["https://github.com/google/highwayhash/archive/08d3f5b4d351d2202531ff22f2ba2e0e0e9865e7.zip"],  # 2019-02-22
    build_file = "@com_google_riegeli//third_party:highwayhash.BUILD",
)

http_archive(
    name = "net_zstd",
    sha256 = "b6c537b53356a3af3ca3e621457751fa9a6ba96daf3aebb3526ae0f610863532",
    strip_prefix = "zstd-1.4.5/lib",
    urls = ["https://github.com/facebook/zstd/archive/v1.4.5.zip"],  # 2020-05-22
    build_file = "@com_google_riegeli//third_party:net_zstd.BUILD",
)

http_archive(
    name = "build_bazel_rules_apple",
    sha256 = "86025f64d723a66438787d089bea4a7bc387877229f927dcb72ee26a8db96917",
    url = "https://github.com/bazelbuild/rules_apple/releases/download/3.9.2/rules_apple.3.9.2.tar.gz",
)

load(
    "@build_bazel_rules_apple//apple:repositories.bzl",
    "apple_rules_dependencies",
)

apple_rules_dependencies()

load(
    "@build_bazel_rules_swift//swift:repositories.bzl",
    "swift_rules_dependencies",
)

swift_rules_dependencies()

load(
    "@build_bazel_rules_swift//swift:extras.bzl",
    "swift_rules_extra_dependencies",
)

swift_rules_extra_dependencies()

load(
    "@build_bazel_apple_support//lib:repositories.bzl",
    "apple_support_dependencies",
)

apple_support_dependencies()